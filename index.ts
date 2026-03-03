import * as tracCryptoApi from 'trac-crypto-api'
import b4a from 'b4a'

type Signature = Buffer
type Message = Buffer
type SecretKey = Buffer
type PulbicKey = Buffer
type KeyPair = { secretKey: SecretKey, publicKey: PulbicKey, address: string }
type HDParams = { mnemonic: string, derivationPath?: string }


/**
 * Sanitizes and validates a derivation path string.
 * Accepts BIP32/BIP44 style paths like m/44'/0'/0'/0'/0'.
 * All segments must be hardened (i.e., end with a prime symbol ').
 * Returns null if invalid.
 * @param {string} derivationPath - The derivation path to sanitize.
 * @returns {string|null} The sanitized derivation path, or null if invalid.
 */
// TODO: Replace this implementation when a similar function is implemented in Trac Crypto Api
const sanitizeDerivationPath = (derivationPath?: string) => {
    if (typeof derivationPath !== 'string') return null;
    const trimmed = derivationPath.trim();
    const bip32HardenedRegex = /^m(\/[0-9]+'?)+$/;
    if (!bip32HardenedRegex.test(trimmed)) return null;
    return trimmed;
}

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


class Wallet {
    #keyPair: KeyPair

    constructor(keypair: KeyPair) {
        this.#keyPair = keypair
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
    verify(signature: Signature, message: Message) {
        return tracCryptoApi.signature.verify(signature, message, this.#keyPair.publicKey)
    }
}

class HDWallet extends Wallet {
    #hdParams: HDParams

    constructor(keypair: KeyPair, hdParams: HDParams) {
        super(keypair)
        this.#hdParams = hdParams
    }

    get mnemonic() {
        return this.#hdParams.mnemonic;
    }

    get derivationPath() {
        return this.#hdParams.derivationPath;
    }
}

export class WalletProvider {
    #networkPrefix
    constructor({ networkPrefix }: { networkPrefix: string }) {
        this.#networkPrefix = networkPrefix
    }

    async fromMnemonic({ mnemonic, derivationPath }: HDParams): Promise<HDWallet> {
        const path = sanitizeDerivationPath(derivationPath)
        const options
            = await tracCryptoApi.address.generate(this.#networkPrefix, mnemonic, path)
        
        // @ts-ignore (should be removed after the js-docs are corrected on trac-core-api)
        return new HDWallet(options, { mnemonic, derivationPath: options.derivationPath })
    }

    async fromSecretKey(secretKey: string): Promise<Wallet> {
        const convertedSk = sanitizeSecretKey(secretKey)
        const options = tracCryptoApi.address.fromSecretKey(this.#networkPrefix, convertedSk)

        return new Wallet(options)
    }

    async generate(seed: string): Promise<HDWallet> {
        const mnemonic = tracCryptoApi.mnemonic.generate(seed)
        return await this.fromMnemonic({ mnemonic })
    }
}