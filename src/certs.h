#include <Security/Security.h>
#include <functional>
#include <string>
#include <vector>

namespace MacosExportCertificateAndKey {

typedef std::function<bool(SecCertificateRef)> CertificatePredicate;

std::vector<std::string> ExportAllCertificates();
std::vector<uint8_t> ExportCertificateAndKey(CertificatePredicate predicate, const std::string& passphrase);
bool IsMatchingCertificate(const std::string& subject, const SecCertificateRef certificate);
bool IsMatchingCertificate(const std::vector<uint8_t>& thumbprint, const SecCertificateRef certificate);

}
