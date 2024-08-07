#include "certs.h"
#include <napi.h>

namespace {

using namespace Napi;
using namespace MacosExportCertificateAndKey;

CertificatePredicate ExportCertificateAndKeyMakePredicate(Object search_spec) {
  if (search_spec.HasOwnProperty("subject")) {
    std::string subject_str = search_spec.Get("subject").ToString().Utf8Value();
    return [subject_str](SecCertificateRef cert) -> bool {
      return IsMatchingCertificate(subject_str, cert);
    };
  } else {
    Buffer<uint8_t> buff = search_spec.Get("thumbprint").As<Buffer<uint8_t>>();
    const uint8_t *data = buff.Data();
    std::vector<uint8_t> thumbprint(data, data + buff.Length());

    return [thumbprint](SecCertificateRef cert) -> bool {
      return IsMatchingCertificate(thumbprint, cert);
    };
  }
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
