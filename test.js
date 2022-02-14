const tls = require('tls');
const fs = require('fs');
const child_process = require('child_process');
const assert = require('assert');
const {
  exportCertificateAndPrivateKey,
  exportSystemCertificates
} = require('./');

describe('exportCertificateAndPrivateKey', () => {
  let tlsServer;
  let authorized;
  let resolveAuthorized;
  let tlsServerConnectOptions;
  before((done) => {
    const serverOpts = {
      key: fs.readFileSync(__dirname + '/testkeys/testserver-privkey.pem'),
      cert: fs.readFileSync(__dirname + '/testkeys/testserver-certificate.pem'),
      requestCert: true,
      ca: [fs.readFileSync(__dirname + '/testkeys/certificate.pem')]
    };
    tlsServer = tls.createServer(serverOpts, (socket) => {
      resolveAuthorized(socket.authorized);
      socket.end();
    });
    tlsServer.listen(0, () => {
      tlsServerConnectOptions = {
        host: 'localhost',
        port: tlsServer.address().port,
        rejectUnauthorized: false
      };
      done();
    });
  })
  beforeEach(() => {
    authorized = new Promise(resolve => resolveAuthorized = resolve);
  });
  after(() => {
    tlsServer.close();
  });

  it('throws when no cert can be found', () => {
    assert.throws(() => {
      exportCertificateAndPrivateKey({ subject: 'Banana Corp '});
    }, /Could not find a matching certificate/);
  });

  it('loads a certificate based on its thumbprint', async() => {
    const { passphrase, pfx } = exportCertificateAndPrivateKey({
      thumbprint: Buffer.from('d755afda2bbad2509d39eca5968553b9103305af', 'hex')
    });
    tls.connect({ ...tlsServerConnectOptions, passphrase, pfx });
    assert.strictEqual(await authorized, true);
  });

  it('loads a certificate based on its subject', async() => {
    const { passphrase, pfx } = exportCertificateAndPrivateKey({
      subject: 'Internet Widgits Pty Ltd'
    });
    tls.connect({ ...tlsServerConnectOptions, passphrase, pfx });
    assert.strictEqual(await authorized, true);
  });
});

describe('exportSystemCertificates', () => {
  it('exports all system certificates', () => {
    const certsFromSecurity = child_process.execSync(
      'security find-certificate -a -p && security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain', {
        encoding: 'utf8'
      })
      .match(/^-----BEGIN\sCERTIFICATE-----[\s\S]+?-----END\sCERTIFICATE-----$/mg)
      .map(str => str.trim());
    const certsFromAddon = exportSystemCertificates()
      .map(str => str.trim());

    assert.deepStrictEqual(new Set(certsFromAddon), new Set(certsFromSecurity));
  });
});
