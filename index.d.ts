declare type LookupOptions = {
  subject: string;
  thumbprint?: never;
} | {
  subject?: never;
  thumbprint: Uint8Array;
};

declare interface PfxResult {
  passphrase: string;
  pfx: Uint8Array;
};

declare function exportCertificateAndPrivateKey(input: LookupOptions): PfxResult;

declare namespace exportCertificateAndPrivateKey {
  function exportCertificateAndPrivateKey(input: LookupOptions): PfxResult;
  function exportCertificateAndPrivateKeyAsync(input: LookupOptions): Promise<PfxResult>;

  function exportSystemCertificates(input: StoreOptions): string[];
  function exportSystemCertificatesAsync(input: StoreOptions): Promise<string[]>;
}

export = exportCertificateAndPrivateKey;
