export type Signature = Buffer | Uint8Array;
export type Message = Buffer | Uint8Array;
export type SecretKey = Buffer | Uint8Array;
export type PublicKey = Buffer | Uint8Array;

export type KeyPair = {
  secretKey: SecretKey;
  publicKey: PublicKey;
  address: string;
};

export type HDParams = {
  mnemonic: string;
  derivationPath?: string;
};
