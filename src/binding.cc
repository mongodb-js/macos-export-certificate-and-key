#include <napi.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonCrypto.h>
#include <Security/Security.h>

namespace {

using namespace Napi;

// Use this when a variable or parameter is unused in order to explicitly
// silence a compiler warning about that.
template <typename T> inline void USE(T&&) {}

typedef std::function<bool(SecCertificateRef)> CertificatePredicate;

template <typename T>
class CFPointer {
  T value_;

 public:
  CFPointer(T val) : value_(val) {
    CFTypeRef value_must_be_a_CFTypeRef = val;
    USE(value_must_be_a_CFTypeRef);
  }

  CFPointer(const CFPointer&) = delete;
  CFPointer& operator=(const CFPointer&) = delete;
  CFPointer(CFPointer&& reference) {
    value_ = reference.value_;
    reference.value_ = nullptr;
  }
  CFPointer& operator=(CFPointer&& reference) {
    if (value_ != nullptr) {
      CFRelease(value_);
    }
    value_ = reference.value_;
    reference.value_ = nullptr;
    return *this;
  }

  ~CFPointer() {
    if (value_ != nullptr) {
      CFRelease(value_);
    }
  }
  T get() { return value_; }
};

const char* getSecErrorString(OSStatus status) {
  CFPointer<CFStringRef> str = SecCopyErrorMessageString(status, NULL);
  return CFStringGetCStringPtr(str.get(), kCFStringEncodingUTF8);
}

void failOnError(OSStatus status, const char* error) {
  if (status != errSecSuccess) {
    char msg[256];
    snprintf(msg, sizeof(msg), "%s: %s", error, getSecErrorString(status));
    throw std::runtime_error(msg);
  }
}

bool isMatchingCertificate(const std::string& subject, const SecCertificateRef certificate) {
  CFPointer<CFStringRef> certSubject(SecCertificateCopySubjectSummary(certificate));
  const char* subj = CFStringGetCStringPtr(certSubject.get(), kCFStringEncodingUTF8);
  return subj != nullptr && subj == subject;
}

bool isMatchingCertificate(const std::vector<uint8_t>& thumbprint, const SecCertificateRef certificate) {
  CFPointer<CFDataRef> certData(SecCertificateCopyData(certificate));

  uint8_t hash_data[std::max(CC_SHA1_DIGEST_LENGTH, CC_SHA256_DIGEST_LENGTH)];
  if (thumbprint.size() == CC_SHA1_DIGEST_LENGTH) {
    CC_SHA1(CFDataGetBytePtr(certData.get()), CFDataGetLength(certData.get()), hash_data);
  } else if (thumbprint.size() == CC_SHA256_DIGEST_LENGTH) {
    CC_SHA256(CFDataGetBytePtr(certData.get()), CFDataGetLength(certData.get()), hash_data);
  } else {
    return false;
  }

  return memcmp(&thumbprint[0], hash_data, thumbprint.size()) == 0;
}

CFMutableDictionaryRef createQueryDictionary(CFStringRef sec_class, bool add_system_keychain) {
  CFPointer<CFMutableArrayRef> new_search_list(nullptr);
  if (add_system_keychain) {
    SecKeychainRef system_roots = nullptr;
    OSStatus kcStatus = SecKeychainOpen("/System/Library/Keychains/SystemRootCertificates.keychain", &system_roots);

    CFArrayRef current_search_list;
    SecKeychainCopySearchList(&current_search_list);
    new_search_list = CFArrayCreateMutableCopy(NULL, 0, current_search_list);
    CFRelease(current_search_list);
    if (!kcStatus) {
      CFArrayAppendValue(new_search_list.get(), system_roots);
      CFRelease(system_roots);
    }
  }

  CFMutableDictionaryRef dict = CFDictionaryCreateMutable(nullptr, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  if (add_system_keychain) {
    CFDictionaryAddValue(dict, kSecMatchSearchList, new_search_list.get());
  }
  CFDictionaryAddValue(dict, kSecClass, sec_class);
  CFDictionaryAddValue(dict, kSecReturnRef, kCFBooleanTrue);
  CFDictionaryAddValue(dict, kSecMatchLimit, kSecMatchLimitAll);
  return dict;
}

CFPointer<SecIdentityRef> findFirstMatchingIdentity(const CFDictionaryRef& query, const CertificatePredicate& predicate) {
  CFArrayRef _items = nullptr;
  OSStatus status = SecItemCopyMatching(query, reinterpret_cast<CFTypeRef*>(&_items));
  failOnError(status, "SecItemCopyMatching failed to load certificates");
  if (CFGetTypeID(_items) != CFArrayGetTypeID()) {
    throw std::runtime_error("Expected SecItemCopyMatching to return an array");
  }

  CFPointer<CFArrayRef> items(_items);
  for (CFIndex i = 0; i < CFArrayGetCount(items.get()); i++) {
    SecIdentityRef identity = reinterpret_cast<SecIdentityRef>(const_cast<void*>(
        CFArrayGetValueAtIndex(items.get(), i)));
    if (CFGetTypeID(identity) != SecIdentityGetTypeID()) {
      throw std::runtime_error("Expected SecItemCopyMatching to return SecIdentityRef items");
    }

    SecCertificateRef certRef;
    OSStatus copyCertStatus = SecIdentityCopyCertificate(identity, &certRef);
    failOnError(copyCertStatus, "SecIdentityCopyCertificate");
    CFPointer<SecCertificateRef> cert(certRef);

    if (predicate(cert.get())) {
      return (SecIdentityRef)CFRetain(identity);
    }
  }

  throw std::runtime_error("Could not find a matching certificate");
}

template<typename SecItem>
CFPointer<CFDataRef> extractCertificateAndPrivateKey(const SecItem& item, const std::string& passphrase, SecExternalFormat format) {
  SecItemImportExportKeyParameters params {};
  if (format == kSecFormatPKCS12) {
    CFStringRef pass = CFStringCreateWithCString(nullptr, passphrase.c_str(), kCFStringEncodingUTF8);
    params.passphrase = pass;
  };

  CFDataRef exportData;
  OSStatus status = SecItemExport(
      item,
      format,
      0,
      &params,
      &exportData);
  failOnError(status, "Failed to export certificate");
  return CFPointer<CFDataRef>(exportData);
}

CertificatePredicate ExportCertificateAndKeyMakePredicate(Object search_spec) {
  if (search_spec.HasOwnProperty("subject")) {
    std::string subject_str = search_spec.Get("subject").ToString().Utf8Value();
    return [subject_str](SecCertificateRef cert) -> bool {
      return isMatchingCertificate(subject_str, cert);
    };
  } else {
    Buffer<uint8_t> buff = search_spec.Get("thumbprint").As<Buffer<uint8_t>>();
    const uint8_t *data = buff.Data();
    std::vector<uint8_t> thumbprint(data, data + buff.Length());

    return [thumbprint](SecCertificateRef cert) -> bool {
      return isMatchingCertificate(thumbprint, cert);
    };
  }
}

std::vector<uint8_t> ExportCertificateAndKey(CertificatePredicate predicate, std::string passphrase) {
  // Filtering for kSecAttrLabel and kSecAttrPublicKeyHash does not work as epxected
  // we look for all identities and filter manually
  CFPointer<CFMutableDictionaryRef> query(createQueryDictionary(kSecClassIdentity, false));
  CFPointer<SecIdentityRef> identity(findFirstMatchingIdentity(query.get(), predicate));

  CFPointer<CFDataRef> exportData = extractCertificateAndPrivateKey(
      identity.get(), passphrase, kSecFormatPKCS12);

  const uint8_t* base = CFDataGetBytePtr(exportData.get());
  const size_t len = CFDataGetLength(exportData.get());
  return std::vector<uint8_t>(base, base + len);
}

std::vector<std::string> ExportAllCertificates() {
  std::vector<std::string> results;

  // Filtering for kSecAttrLabel and kSecAttrPublicKeyHash does not work as epxected
  // we look for all identities and filter manually
  CFPointer<CFMutableDictionaryRef> query(createQueryDictionary(kSecClassCertificate, true));

  CFArrayRef _items = nullptr;
  OSStatus status = SecItemCopyMatching(query.get(), reinterpret_cast<CFTypeRef*>(&_items));
  failOnError(status, "SecItemCopyMatching failed to load certificates");
  if (CFGetTypeID(_items) != CFArrayGetTypeID()) {
    throw std::runtime_error("Expected SecItemCopyMatching to return an array");
  }

  CFPointer<CFArrayRef> items(_items);
  for (CFIndex i = 0; i < CFArrayGetCount(items.get()); i++) {
    SecCertificateRef cert = reinterpret_cast<SecCertificateRef>(const_cast<void*>(
        CFArrayGetValueAtIndex(items.get(), i)));
    if (CFGetTypeID(cert) != SecCertificateGetTypeID()) {
      throw std::runtime_error("Expected SecItemCopyMatching to return SecCertificateRef items");
    }

    CFPointer<CFDataRef> exportData = extractCertificateAndPrivateKey(
        cert, "", kSecFormatPEMSequence);

    results.push_back({
        reinterpret_cast<const char*>(CFDataGetBytePtr(exportData.get())),
        static_cast<size_t>(CFDataGetLength(exportData.get()))
    });
  }

  return results;
}

Value ExportCertificateAndKeySync(const CallbackInfo& args) {
  CertificatePredicate predicate = ExportCertificateAndKeyMakePredicate(args[0].ToObject());
  std::string passphrase = args[1].ToString().Utf8Value();

  try {
    const auto& result = ExportCertificateAndKey(std::move(predicate), std::move(passphrase));
    return Buffer<uint8_t>::Copy(args.Env(), result.data(), result.size());
  } catch (const std::exception& e) {
    throw Error::New(args.Env(), e.what());
  }
}

Value ExportAllCertificatesSync(const CallbackInfo& args) {
  Env env = args.Env();
  Array results = Array::New(env);

  try {
    auto result = ExportAllCertificates();
    if (result.size() > static_cast<uint32_t>(-1)) {
      throw std::runtime_error("result length exceeds uint32 max");
    }
    for (uint32_t i = 0; i < result.size(); i++) {
      results[i] = String::New(args.Env(), std::move(result[i]));
    }

    return results;
  } catch (const std::exception& e) {
    throw Error::New(env, e.what());
  }
}

} // anonymous namespace

static Object InitMacosExportCertificateAndKey(Env env, Object exports) {
  exports["exportCertificateAndKey"] = Function::New(env, ExportCertificateAndKeySync);
  exports["exportAllCertificates"] = Function::New(env, ExportAllCertificatesSync);
  return exports;
}

NODE_API_MODULE(macos_export_certificate_and_key, InitMacosExportCertificateAndKey)
