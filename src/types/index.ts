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

/**
 * Basic stateful facility for message verification
 */
export interface IVerifier {
  readonly publicKey: PublicKey;
  verify(signature: Signature, message: Message): boolean;
}

/**
 * Basic wallet interface for signing, verification and serialization. Created from a secret key.
 */
export interface IWallet extends IVerifier {
  readonly secretKey: SecretKey;
  readonly address: string;
  sign(message: Message): Signature;
  equals(wallet: IWallet): boolean;
  asJson(): string;
}

/**
 * Hierarchical deterministic wallet interface. Created from a mnemonic.
 */
export interface IHDWallet extends IWallet {
  readonly mnemonic: string;
  readonly derivationPath?: string;
}
