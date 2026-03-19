/** @typedef {import('pear-interface')} */
import * as tracCryptoApi from 'trac-crypto-api'
import b4a from 'b4a'
import type { HDParams, IHDWallet, KeyPair, Message, Signature, IWallet, KeyStoreVersion } from './types/index.ts'

export const CURRENT_VERSION: KeyStoreVersion = '1.0.0'

const sanitizeSecretKey = (secretKey: string) => {
    try {
        const buffer = b4a.from(secretKey, 'hex');
        if (buffer.length !== tracCryptoApi.address.PRIV_KEY_SIZE) {
            throw new Error('Invalid secret key length');
        }
        return buffer;
    } catch (error) {
        throw new Error('Invalid secret key format. Please provide a valid hex string');
    }
}

const sanitizeMnemonic = (mnemonic: string) => {
    const sanitized = tracCryptoApi.mnemonic.sanitize(mnemonic)
    if (sanitized === null) {
        throw new Error('Invalid mnemonic, please provide a valid one');
    }

    return sanitized
}

class Wallet implements IWallet {
    #keyPair: KeyPair
    #addressPrefix: string

    constructor(addressPrefix: string, keypair: KeyPair) {
        this.#addressPrefix = addressPrefix
        this.#keyPair = keypair
    }

    get addressPrefix() {
        return this.#addressPrefix;
    }

    get publicKey() {
        return this.#keyPair.publicKey;
    }

    get secretKey() {
        return this.#keyPair.secretKey;
    }

    get address() {
        return this.#keyPair.address;
    }

    /**
     * Signs a message using the wallet's stored secret key.
     * @param {Message} message - The message to sign.
     * @returns {Signature} The signature as a Buffer, or empty Buffer on error.
     */
    sign(message: Message): Signature {
        return tracCryptoApi.sign(message, this.#keyPair.secretKey)
    }

    /**
     * Verifies a signature using the wallet's public key.
     * @param {Signature} signature - The signature to verify.
     * @param {Message} message - The message to verify.
     * @returns {boolean} true if valid, false otherwise.
     */
    verify(signature: Signature, message: Message): boolean {
        return tracCryptoApi.signature.verify(signature, message, this.#keyPair.publicKey)
    }

    /**
     * Verifies if both wallets are equal
     * @param {IWallet} other - The wallet to compare with
     * @returns {boolean} true if valid, false otherwise.
     */
    equals(other: IWallet): boolean {
        return this.address === other.address
    }

    /**
     * Produces a string (json) representation of the wallet.
     * @returns {string} the wallet as json
     */
    asJson(): string {
        const toExport = {
            addressPrefix: this.addressPrefix,
            publicKey: b4a.toString(this.publicKey, 'hex'),
            secretKey: b4a.toString(this.secretKey, 'hex'),
            address: this.address,
            version: CURRENT_VERSION
        };

        return JSON.stringify(toExport, null, 2);
    }
}

class HDWallet extends Wallet implements IHDWallet {
    #hdParams: HDParams

    constructor(addressPrefix: string, keypair: KeyPair, hdParams: HDParams) {
        super(addressPrefix, keypair)
        this.#hdParams = hdParams
    }

    get mnemonic() {
        return this.#hdParams.mnemonic;
    }

    get derivationPath() {
        return this.#hdParams.derivationPath;
    }

    asJson(): string {
        const toExport = {
            addressPrefix: this.addressPrefix,
            publicKey: b4a.toString(this.publicKey, 'hex'),
            secretKey: b4a.toString(this.secretKey, 'hex'),
            address: this.address,
            mnemonic: this.mnemonic,
            derivationPath: this.derivationPath,
            version: CURRENT_VERSION
        };

        return JSON.stringify(toExport, null, 2);
    }
}

export class WalletProvider {
    #addressPrefix

    /**
     * Creates a wallet provider bound to an address prefix. 
     * @param {{ addressPrefix: string }} options - Provider options. 
     * @param {string} options.addressPrefix - Address HRP prefix (for example `trac` or `tractest`).
     */
    constructor({ addressPrefix }: { addressPrefix: string }) {
        this.#addressPrefix = addressPrefix
    }

    /**
     * Creates an HD wallet from a mnemonic and optional derivation path.
     * @param {HDParams} params - Mnemonic and derivation path.
     * @returns {Promise<IHDWallet>} The generated HD wallet.
     * @throws {Error} If mnemonic or derivation path are invalid. Bubbles up other crypto-related errors.
     */
    async fromMnemonic({ mnemonic, derivationPath = tracCryptoApi.address.DEFAULT_DERIVATION_PATH }: HDParams): Promise<IHDWallet> {
        const sanitizedMnemonic = sanitizeMnemonic(mnemonic)
        const options
            = await tracCryptoApi.address.generate(this.#addressPrefix, sanitizedMnemonic, derivationPath) // This sanitizes the derivation path

        // @ts-ignore (should be removed after the js-docs are corrected on trac-core-api)
        return new HDWallet(this.#addressPrefix, options, { mnemonic: sanitizedMnemonic, derivationPath: options.derivationPath })
    }

    /**
     * Creates a wallet from a hex-encoded secret key.
     * @param {string} secretKey - Secret key as a hex string.
     * @returns {Promise<IWallet>} The wallet derived from the secret key.
     * @throws {Error} If the secret key format or length are invalid. Bubbles up other crypto-related errors.
     */
    async fromSecretKey(secretKey: string): Promise<IWallet> {
        const convertedSk = sanitizeSecretKey(secretKey)
        const options = tracCryptoApi.address.fromSecretKey(this.#addressPrefix, convertedSk)

        return new Wallet(this.#addressPrefix, options)
    }

    /**
     * Generates a new HD wallet using an optional deterministic seed.
     * @param {string} [seed] - Optional seed for deterministic mnemonic generation.
     * @returns {Promise<IHDWallet>} The generated HD wallet.
     */
    async generate(seed?: string): Promise<IHDWallet> {
        const mnemonic = tracCryptoApi.mnemonic.generate(seed)
        return await this.fromMnemonic({ mnemonic })
    }
}
