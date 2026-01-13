const tls = require('tls');
const fs = require('fs');
const child_process = require('child_process');
const assert = require('assert');
const {
  exportCertificateAndPrivateKey,
  exportCertificateAndPrivateKeyAsync,
  exportSystemCertificates,
  exportSystemCertificatesAsync
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

  for (const method of ['sync', 'async']) {
    const fn = {
      sync: exportCertificateAndPrivateKey,
      async: exportCertificateAndPrivateKeyAsync
    }[method];
    context(method, () => {
      it('throws when no cert can be found', async() => {
        await assert.rejects(async() => {
          await fn({ subject: 'Banana Corp '});
        }, /Could not find a matching certificate/);
      });

      it('loads a certificate based on its thumbprint', async() => {
        const { passphrase, pfx } = await fn({
          thumbprint: Buffer.from('0d973f73b5dfea326162037f487a1207c48c9042', 'hex')
        });
        tls.connect({ ...tlsServerConnectOptions, passphrase, pfx });
        assert.strictEqual(await authorized, true);
      });

      it('loads a certificate based on its subject', async() => {
        const { passphrase, pfx } = await fn({
          subject: 'Internet Widgits Pty Ltd'
        });
        tls.connect({ ...tlsServerConnectOptions, passphrase, pfx });
        assert.strictEqual(await authorized, true);
      });
    });
  }
});

describe('exportSystemCertificates', () => {
  for (const method of ['sync', 'async']) {
    const fn = {
      sync: exportSystemCertificates,
      async: exportSystemCertificatesAsync
    }[method];
    context(method, () => {
      it('exports all system certificates', async() => {
        const certsFromSecurity = child_process.execSync(
          'security find-certificate -a -p && security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain', {
            encoding: 'utf8'
          })
          .match(/^-----BEGIN\sCERTIFICATE-----[\s\S]+?-----END\sCERTIFICATE-----$/mg)
          .map(str => str.trim());
        const certsFromAddon = (await fn())
          .map(str => str.trim());

        assert.deepStrictEqual(new Set(certsFromAddon), new Set(certsFromSecurity));
      });
    });
  }
});
