export type Signature = Uint8Array;
export type Message = Uint8Array;
export type SecretKey = Uint8Array;
export type PublicKey = Uint8Array;

export type KeyPair = {
  secretKey: SecretKey;
  publicKey: PublicKey;
  address: string;
};

export type HDParams = {
  mnemonic: string;
  derivationPath?: string;
};
