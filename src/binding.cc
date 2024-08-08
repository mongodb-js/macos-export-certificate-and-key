#include "certs.h"
#include <napi.h>

#define PACKAGE "macos-export-certificate-and-key"

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

Array StringListToArray(Env env, const std::vector<std::string>& vec) {
  Array ret = Array::New(env);
  if (vec.size() > static_cast<uint32_t>(-1)) {
    throw std::runtime_error("result length exceeds uint32 max");
  }
  for (uint32_t i = 0; i < vec.size(); i++) {
    ret[i] = String::New(env, std::move(vec[i]));
  }
  return ret;
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

  try {
    return StringListToArray(env, ExportAllCertificates());
  } catch (const std::exception& e) {
    throw Error::New(env, e.what());
  }
}

Value ExportCertificateAndKeyAsync(const CallbackInfo& args) {
  class Worker final : public AsyncWorker {
    public:
      Worker(Function callback, CertificatePredicate&& predicate, std::string&& passphrase)
        : AsyncWorker(callback, PACKAGE ":ExportCertificateAndKey"),
        predicate(std::move(predicate)),
        passphrase(std::move(passphrase)) {}
      ~Worker() {}

      void Execute() override {
        result = ExportCertificateAndKey(std::move(predicate), std::move(passphrase));
      }

      void OnOK() override {
        try {
          Callback().Call({Env().Null(), Buffer<uint8_t>::Copy(Env(), result.data(), result.size())});
        } catch (const std::exception& e) {
          throw Error::New(Env(), e.what());
        }
      }

    private:
      std::vector<uint8_t> result;
      CertificatePredicate predicate;
      std::string passphrase;
  };

  Worker* worker = new Worker(
      args[2].As<Function>(),
      ExportCertificateAndKeyMakePredicate(args[0].ToObject()),
      args[1].ToString().Utf8Value());
  worker->Queue();
  return args.Env().Undefined();
}

Value ExportAllCertificatesAsync(const CallbackInfo& args) {
  class Worker final : public AsyncWorker {
    public:
      Worker(Function callback)
        : AsyncWorker(callback, PACKAGE ":ExportAllCertificates") {}
      ~Worker() {}

      void Execute() override {
        results = ExportAllCertificates();
      }

      void OnOK() override {
        try {
          Callback().Call({Env().Null(), StringListToArray(Env(), results)});
        } catch (const std::exception& e) {
          throw Error::New(Env(), e.what());
        }
      }

    private:
      std::vector<std::string> results;
  };

  Worker* worker = new Worker(args[0].As<Function>());
  worker->Queue();
  return args.Env().Undefined();
}

} // anonymous namespace

static Object InitMacosExportCertificateAndKey(Env env, Object exports) {
  exports["exportCertificateAndKey"] = Function::New(env, ExportCertificateAndKeySync);
  exports["exportAllCertificates"] = Function::New(env, ExportAllCertificatesSync);
  exports["exportCertificateAndKeyAsync"] = Function::New(env, ExportCertificateAndKeyAsync);
  exports["exportAllCertificatesAsync"] = Function::New(env, ExportAllCertificatesAsync);
  return exports;
}

NODE_API_MODULE(macos_export_certificate_and_key, InitMacosExportCertificateAndKey)
