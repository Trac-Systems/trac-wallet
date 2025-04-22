/** @typedef {import('pear-interface')} */
import { generateMnemonic, validateMnemonic, mnemonicToSeed } from 'bip39-mnemonic';
import sodium from 'sodium-universal'
import b4a from 'b4a';
const size = 128; // 12 words. Size equal to 256 is 24 words.

// TODO: Decide if this should continue being an internal-only class or if it should be exported
export class Wallet {
    #keyPair; // TODO: This needs to be in a secure storage, not in memory. This is just a temporary solution.
    #isVerifyOnly;

    /**
     * Creates a new Wallet instance.
     * @param {Object} options - An object containing the following properties:
     * @param {string} options.mnemonic - The mnemonic phrase to use for key generation.
     * @param {boolean} options.isVerifyOnly - A flag to indicate if the wallet will only be used for verifying signatures. If true, the key pair will not be generated.
     */
    constructor(options = {}) {
        this.#isVerifyOnly = options.isVerifyOnly || false;

        this.#keyPair = {
            publicKey: null,
            secretKey: null
        };

        if (options.mnemonic && !this.#isVerifyOnly) {
            // TODO / WARNING: Calling an async function in a constructor is not recommended.
            // This may cause errors in production code. Consider refactoring this to use a factory method.
            this.generateKeyPair(options.mnemonic);
        }
    }

    /**
     * Returns the public key as a hex string.
     * @returns {string|null} The public key in hex format or null if not set.
     */
    get publicKey() {
        if (!this.#keyPair.publicKey) {
            return null;
        }
        return this.#keyPair.publicKey.toString('hex');
    }

    get secretKey() {
        if (!this.#keyPair.secretKey) {
            return null;
        }
        return this.#keyPair.secretKey.toString('hex');
    }

    /**
     * Returns the flag indicating if the wallet is set to verify only mode.
     * @returns {boolean} True if the wallet is set to verify only, false otherwise.
     */
    get isVerifyOnly() {
        return this.#isVerifyOnly;
    }

    /**
     * Sets the key pair directly. If the wallet is set to verifyOnly mode, it will return to standard mode
     * @param {Object} keyPair - An object containing the publicKey and secretKey as hex strings.
     * @throws Will throw an error if the wallet is set to verify only.
     * @throws Will throw an error if the key pair is invalid.
     */
    set keyPair(keyPair) {
        if (this.#isVerifyOnly) {
            throw new Error('This wallet is set to verify only. Please create a new wallet instance with a valid mnemonic to generate a key pair');
        }
        if (!keyPair || !keyPair.publicKey || !keyPair.secretKey) {
            throw new Error('Invalid key pair. Please provide a valid object with publicKey and secretKey');
        }
        this.#keyPair = this.sanitizeKeyPair(keyPair.publicKey, keyPair.secretKey);
    }

    /**
     * Verifies a message signature.
     * @param {string || Buffer} signature - The signature in hex or Buffer format.
     * @param {string || Buffer} message - The message to verify in string or Buffer.
     * @param {string || Buffer} publicKey - The public key in hex or Buffer format.
     * @returns {boolean} True if the signature is valid, false otherwise.
     */
    verify(signature, message, publicKey) {
        try {
            const signatureBuffer = b4a.isBuffer(signature) ? signature : b4a.from(signature, 'hex');
            const messageBuffer = b4a.isBuffer(message) ? message : b4a.from(message);
            const publicKeyBuffer = b4a.isBuffer(publicKey) ? publicKey : b4a.from(publicKey, 'hex');
            return sodium.crypto_sign_verify_detached(signatureBuffer, messageBuffer, publicKeyBuffer);
        } catch (e) { console.log(e) }
        return false;
    }

    /**
     * Generates a new mnemonic phrase.
     * @returns {string} A new mnemonic phrase.
     */
    generateMnemonic() {
        return generateMnemonic(size);
    }

    /**
     * Creates a cryptographic hash of a given message using the specified algorithm.
     *
     * @param {string} type - The hash algorithm to use. Supported values: 'sha256', 'sha1', 'sha384', 'sha512'.
     * @param {string} message - The input message to hash.
     * @returns {Promise<string>} A promise that resolves to the hash value as a hexadecimal string.
     * @throws {Error} Throws an error if the algorithm type is unsupported or if hashing fails.
     */
    async createHash(type, message) {
        if (type === 'sha256') {
            const out = b4a.alloc(sodium.crypto_hash_sha256_BYTES || 32);
            sodium.crypto_hash_sha256(out, b4a.from(message));  // Zamiast sha256 używamy sodium.crypto_hash_sha256
            return b4a.toString(out, 'hex');
        }
        if (global.Pear !== undefined) {
            let _type = '';
            switch (type.toLowerCase()) {
                case 'sha1': _type = 'SHA-1'; break;
                case 'sha384': _type = 'SHA-384'; break;
                case 'sha512': _type = 'SHA-512'; break;
                default: throw new Error('Unsupported algorithm.');
            }
            const encoder = new TextEncoder();
            const data = encoder.encode(message);
            const hash = await crypto.subtle.digest(_type, data);
            const hashArray = Array.from(new Uint8Array(hash));
            return hashArray
                .map((b) => b.toString(16).padStart(2, "0"))
                .join("");
        } 
    }
    
    /**
     * Generates a key pair from a mnemonic phrase. If the wallet is set to verifyOnly mode, it will return to standard mode
     * @param {string} mnemonic - The mnemonic phrase.
     * @throws Will throw an error if the wallet is set to verify only.
     * @throws Will throw an error if the mnemonic is invalid.
     */
    async generateKeyPair(mnemonic) {
        if (this.#isVerifyOnly) {
            throw new Error('This wallet is set to verify only. Please create a new wallet instance with a valid mnemonic to generate a key pair');
        }

        // TODO: Include a warning stating that the previous keys will be deleted if a new mnemonic is provided
        let safeMnemonic = this.sanitizeMnemonic(mnemonic);

        // TODO: Should we just return an error instead? The user will not be able backup the keys if we do this
        if (!safeMnemonic) {
            safeMnemonic = generateMnemonic();
        }

        const seed = await mnemonicToSeed(safeMnemonic);

        const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES);
        const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES);

        const seed32 = b4a.from(await this.createHash('sha256', seed), 'hex');

        sodium.crypto_sign_seed_keypair(publicKey, secretKey, seed32);

        this.#keyPair.publicKey = publicKey;
        this.#keyPair.secretKey = secretKey;
    }

    /**
     * Signs a message with the stored secret key.
     * @param {string} message - The message to sign.
     * @param {Buffer} privateKey - The private key to use for signing. If not provided, the stored secret key will be used.
     * @returns {string} The signature in hex format.
     * @throws Will throw an error if the wallet is set to verify only.
     * @throws Will throw an error if the secret key is not set.
     */
    sign(message, privateKey = null) {
        if (this.#isVerifyOnly) {
            throw new Error('This wallet is set to verify only. Please create a new wallet instance with a valid mnemonic to generate a key pair');
        }

        if (!this.#keyPair.secretKey && !privateKey) {
            throw new Error('No key pair found. Please, generate a key pair first');
        }

        const keyToUse = privateKey || this.#keyPair.secretKey;

        if (!b4a.isBuffer(keyToUse)) {
            throw new Error('Private key must be a Buffer');
        }

        if (keyToUse.length !== sodium.crypto_sign_SECRETKEYBYTES) {
            throw new Error('Invalid private key length');
        }

        const messageBuffer = b4a.isBuffer(message) ? message : b4a.from(message);
        const signature = b4a.alloc(sodium.crypto_sign_BYTES);
        sodium.crypto_sign_detached(signature, messageBuffer, keyToUse);
        return signature.toString('hex');
    }

    /**
     * Exports the key pair to a JSON file.
     * @param {string} filePath - The path to the file where the keys will be saved.
     * @throws Will throw an error if the key pair is not set.
     */



    /**
     * Sanitizes and validates a mnemonic phrase.
     * @param {string} mnemonic - The mnemonic phrase to sanitize.
     * @returns {string|null} The sanitized mnemonic or null if the input is invalid.
     * @throws Will throw an error if the mnemonic is invalid.
     */
    sanitizeMnemonic(mnemonic) {
        if (!mnemonic) {
            return null;
        }
        const sanitized = mnemonic.toLowerCase().trim().split(' ').filter(word => word.trim()).join(' ');

        // Check if all words are valid
        if (!validateMnemonic(sanitized)) {
            throw new Error('Invalid mnemonic. Please, provide a valid mnemonic');
        }

        return sanitized;
    }

    /**
     * Sanitizes and validates a public key.
     * @param {string} publicKey - The public key in hex format.
     * @returns {Buffer} The sanitized public key as a buffer.
     * @throws Will throw an error if the public key is invalid.
     */
    sanitizePublicKey(publicKey) {
        try {
            const buffer = b4a.from(publicKey, 'hex');
            if (buffer.length !== sodium.crypto_sign_PUBLICKEYBYTES) {
                throw new Error('Invalid public key length');
            }
            return buffer;
        } catch (error) {
            throw new Error('Invalid public key format. Please provide a valid hex string');
        }
    }

    /**
     * Sanitizes and validates a secret key.
     * @param {string} secretKey - The secret key in hex format.
     * @returns {Buffer} The sanitized secret key as a buffer.
     * @throws Will throw an error if the secret key is invalid.
     */
    sanitizeSecretKey(secretKey) {
        try {
            const buffer = b4a.from(secretKey, 'hex');
            if (buffer.length !== sodium.crypto_sign_SECRETKEYBYTES) {
                throw new Error('Invalid secret key length');
            }
            return buffer;
        } catch (error) {
            throw new Error('Invalid secret key format. Please provide a valid hex string');
        }
    }

    /**
     * Sanitizes and validates a key pair.
     * @param {string} publicKey - The public key in hex format.
     * @param {string} secretKey - The secret key in hex format.
     * @returns {Object} An object containing the sanitized publicKey and secretKey as buffers.
     */
    sanitizeKeyPair(publicKey, secretKey) {
        return {
            publicKey: this.sanitizePublicKey(publicKey),
            secretKey: this.sanitizeSecretKey(secretKey)
        };
    }
}

export default Wallet;