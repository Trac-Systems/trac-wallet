/** @typedef {import('pear-interface')} */
import * as tracCryptoApi from 'trac-crypto-api'
import b4a from 'b4a'
import type { HDParams, IHDWallet, KeyPair, Message, Signature, IWallet } from './types/index.ts'

/**
 * Sanitizes and validates a secret key.
 * @param {string} secretKey - The secret key in hex format.
 * @returns {Buffer} The sanitized secret key as a Buffer.
 * @throws {Error} If the secret key is invalid.
 */
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

/**
 * Sanitizes and validates a mnemonic.
 * @param {string} mnemonic - The mnemonic.
 * @returns {string} The sanitized mnemonic
 * @throws {Error} If the mnemonic is invalid.
 */
const sanitizeMnemonic = (mnemonic: string) => {    
    const sanitized = tracCryptoApi.mnemonic.sanitize(mnemonic)
    if (sanitized === null) {
        throw new Error('Invalid secret key format. Please provide a valid hex string');
    }

    return sanitized
}

class Wallet implements IWallet {
    #keyPair: KeyPair
    #networkPrefix: string

    constructor(networkPrefix: string, keypair: KeyPair) {
        this.#networkPrefix = networkPrefix
        this.#keyPair = keypair
    }

    get networkPrefix() {
        return this.#networkPrefix;
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
     * @param {Message} signature - The signature to verify.
     * @param {Signature} message - The message to verify.
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
            networkPrefix: this.networkPrefix,
            publicKey: b4a.toString(this.publicKey, 'hex'),
            secretKey: b4a.toString(this.secretKey, 'hex'),
            address: this.address
        };

        return JSON.stringify(toExport, null, 2);
    }
}

class HDWallet extends Wallet implements IHDWallet {
    #hdParams: HDParams

    constructor(networkPrefix: string, keypair: KeyPair, hdParams: HDParams) {
        super(networkPrefix, keypair)
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
            networkPrefix: this.networkPrefix,
            publicKey: b4a.toString(this.publicKey, 'hex'),
            secretKey: b4a.toString(this.secretKey, 'hex'),
            address: this.address,
            mnemonic: this.mnemonic,
            derivationPath: this.derivationPath
        };

        return JSON.stringify(toExport, null, 2);
    }
}

export class WalletProvider {
    #networkPrefix
    constructor({ networkPrefix }: { networkPrefix: string }) {
        this.#networkPrefix = networkPrefix
    }

    async fromMnemonic({ mnemonic, derivationPath = tracCryptoApi.address.DEFAULT_DERIVATION_PATH }: HDParams): Promise<IHDWallet> {
        const sanitizedMnemonic = sanitizeMnemonic(mnemonic)
        const options
            = await tracCryptoApi.address.generate(this.#networkPrefix, sanitizedMnemonic, derivationPath) // This sanitizes the derivation path
        
        // @ts-ignore (should be removed after the js-docs are corrected on trac-core-api)
        return new HDWallet(this.#networkPrefix, options, { mnemonic: sanitizedMnemonic, derivationPath: options.derivationPath })
    }

    async fromSecretKey(secretKey: string): Promise<IWallet> {
        const convertedSk = sanitizeSecretKey(secretKey)
        const options = tracCryptoApi.address.fromSecretKey(this.#networkPrefix, convertedSk)

        return new Wallet(this.#networkPrefix, options)
    }

    async generate(seed?: string): Promise<IHDWallet> {
        const mnemonic = tracCryptoApi.mnemonic.generate(seed)
        return await this.fromMnemonic({ mnemonic })
    }
}

export type { IWallet, IHDWallet } from './types/index.ts'
