const {
  exportCertificateAndKey,
  exportCertificateAndKeyAsync,
  exportAllCertificates,
  exportAllCertificatesAsync
} = require('bindings')('macos_export_certificate_and_key');
const { randomBytes } = require('crypto');
const util = require('util');
const { promisify } = util;

function validateSubjectAndThumbprint(subject, thumbprint) {
  if (!subject && !thumbprint) {
    throw new Error('Need to specify either `subject` or `thumbprint`');
  }
  if (subject && thumbprint) {
    throw new Error('Cannot specify both `subject` and `thumbprint`');
  }
  if (subject && typeof subject !== 'string') {
    throw new Error('`subject` needs to be a string');
  }
  if (thumbprint && !util.types.isUint8Array(thumbprint)) {
    throw new Error('`thumbprint` needs to be a Uint8Array');
  }
}

function exportCertificateAndPrivateKey({
  subject,
  thumbprint
}) {
validateSubjectAndThumbprint(subject, thumbprint);
const passphrase = randomBytes(12).toString('hex');
const pfx = exportCertificateAndKey(
  subject ? { subject } : { thumbprint },
  passphrase
);
return { passphrase, pfx };
};

async function exportCertificateAndPrivateKeyAsync({
  subject,
  thumbprint
}) {
  validateSubjectAndThumbprint(subject, thumbprint);
  const passphrase = (await promisify(randomBytes)(12)).toString('hex');
  const pfx = await promisify(exportCertificateAndKeyAsync)(
    subject ? { subject } : { thumbprint },
    passphrase
  );
  return { passphrase, pfx };
};

module.exports = exportCertificateAndPrivateKey;
module.exports.exportCertificateAndPrivateKey = exportCertificateAndPrivateKey;
module.exports.exportCertificateAndPrivateKeyAsync = exportCertificateAndPrivateKeyAsync;
module.exports.exportSystemCertificates = exportAllCertificates;
module.exports.exportSystemCertificatesAsync = promisify(exportAllCertificatesAsync);
