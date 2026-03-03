export type Signature = Buffer;
export type Message = Buffer;
export type SecretKey = Buffer;
export type PublicKey = Buffer;

export type KeyPair = {
  secretKey: SecretKey;
  publicKey: PublicKey;
  address: string;
};

export type HDParams = {
  mnemonic: string;
  derivationPath?: string;
};
