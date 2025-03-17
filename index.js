import * as bip39 from 'bip39';
import sodium from 'sodium-native';
import * as crypto from 'crypto';
import * as fs from 'fs';

const size = 128; // 12 words. Size equal to 256 is 24 words.

export class Wallet {
    #keyPair; // TODO: This needs to be in a secure storage, not in memory. This is just a temporary solution.

    constructor(mnemonic) {
        this.#keyPair = {
            publicKey: null,
            secretKey: null
        };

        if (mnemonic) {
            this.generateKeyPair(mnemonic);
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

    /**
     * Sets the key pair directly
     * @param {Object} keyPair - An object containing the publicKey and secretKey as hex strings.
     * @throws Will throw an error if the key pair is invalid.
     */
    set keyPair(keyPair) {
        if (!keyPair.publicKey || !keyPair.secretKey) {
            throw new Error('Invalid key pair. Please provide a valid object with publicKey and secretKey');
        }
        this.#keyPair = this.sanitizeKeyPair(keyPair.publicKey, keyPair.secretKey);
    }

    /**
     * Verifies a message signature.
     * @param {string} signature - The signature in hex format.
     * @param {string} message - The message to verify.
     * @param {string} publicKey - The public key in hex format.
     * @returns {boolean} True if the signature is valid, false otherwise.
     */
    verify(signature, message, publicKey) {
        const signatureBuffer = Buffer.from(signature, 'hex');
        const messageBuffer = Buffer.from(message);
        const publicKeyBuffer = Buffer.from(publicKey, 'hex');
        return sodium.crypto_sign_verify_detached(signatureBuffer, messageBuffer, publicKeyBuffer);
    }

    /**
     * Generates a new mnemonic phrase.
     * @returns {string} A new mnemonic phrase.
     */
    generateMnemonic() {
        return bip39.generateMnemonic(size);
    }

    /**
     * Generates a key pair from a mnemonic phrase.
     * @param {string} mnemonic - The mnemonic phrase.
     * @throws Will throw an error if the mnemonic is invalid.
     */
    generateKeyPair(mnemonic) {
        // TODO: Include a warning stating that the previous keys will be deleted if a new mnemonic is provided
        let safeMnemonic = this.sanitizeMnemonic(mnemonic);

        // TODO: Should we just return an error instead? The user will not be able backup the keys if we do this
        if (!safeMnemonic) {
            safeMnemonic = bip39.generateMnemonic(size);
        }

        const seed = bip39.mnemonicToSeedSync(safeMnemonic);

        const publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES);
        const secretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES);

        const seed32 = crypto.createHash('sha256').update(seed).digest();
        const seed32buffer = Buffer.from(seed32);

        sodium.crypto_sign_seed_keypair(publicKey, secretKey, seed32buffer);

        this.#keyPair.publicKey = publicKey;
        this.#keyPair.secretKey = secretKey;
    }

    /**
     * Signs a message with the stored secret key.
     * @param {string} message - The message to sign.
     * @returns {string} The signature in hex format.
     * @throws Will throw an error if the secret key is not set.
     */
    sign(message) {
        if (!this.#keyPair.secretKey) {
            throw new Error('No key pair found. Please, generate a key pair first');
        }
        const messageBuffer = Buffer.from(message);
        const signature = Buffer.alloc(sodium.crypto_sign_BYTES);
        sodium.crypto_sign_detached(signature, messageBuffer, this.#keyPair.secretKey);
        return signature.toString('hex');
    }

    /**
     * Exports the key pair to a JSON file.
     * @param {string} filePath - The path to the file where the keys will be saved.
     * @throws Will throw an error if the key pair is not set.
     */
    exportToFile(filePath) {
        if (!this.#keyPair.secretKey) {
            throw new Error('No key pair found');
        }
        const data = {
            publicKey: this.#keyPair.publicKey.toString('hex'),
            secretKey: this.#keyPair.secretKey.toString('hex')
        };
        fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    }
    
    /**
     * Imports a key pair from a JSON file.
     * @param {string} filePath - The path to the file where the keys are saved.
     */
    importFromFile(filePath) {
        const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        this.#keyPair = this.sanitizeKeyPair(data.publicKey, data.secretKey);
    }

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
        const words = sanitized.split(' ');
        if (words.length !== 12 || !bip39.validateMnemonic(sanitized)) {
            throw new Error('Invalid mnemonic. Please, provide a valid 12-word mnemonic');
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
            const buffer = Buffer.from(publicKey, 'hex');
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
            const buffer = Buffer.from(secretKey, 'hex');
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