import * as bip39 from 'bip39';
import sodium from 'sodium-native';
import * as crypto from 'crypto';
import * as fs from 'fs';

const size = 128; // 12 words. Size equal to 256 is 24 words.

export class Wallet {
    #keyPair; // TODO: This needs to be in a secure storage, not in memory. This is just a temporary solution.

    constructor(mnemonicInput) {
        this.#keyPair = {
            publicKey: null,
            secretKey: null
        };

        if (mnemonicInput) {
            this.generateKeyPair(mnemonicInput);
        }
    }

    get publicKey() {
        return this.#keyPair.publicKey;
    }

    verifySignature(message, signature, publicKey) {
        const messageBuffer = Buffer.from(message);
        return sodium.crypto_sign_verify_detached(signature, messageBuffer, publicKey);
    }

    generateMnemonic() {
        return bip39.generateMnemonic(size)
    }

    generateKeyPair(mnemonicInput) {
        // TODO: Include a warning stating that the previous keys will be deleted if a new mnemonic is provided
        let mnemonic = this.#sanitizeMnemonic(mnemonicInput);

        // TODO: Should we just return an error instead? The user will not be able backup the keys if we do this
        if (!mnemonic) {
            mnemonic = bip39.generateMnemonic(size);
        }

        const seed = bip39.mnemonicToSeedSync(mnemonic);

        const publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES);
        const secretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES);

        const seed32 = crypto.createHash('sha256').update(seed).digest();
        const seed32buffer = Buffer.from(seed32);

        sodium.crypto_sign_seed_keypair(publicKey, secretKey, seed32buffer);

        this.#keyPair.publicKey = publicKey;
        this.#keyPair.secretKey = secretKey;
    }

    signMessage(message) {
        if (!this.#keyPair.secretKey) {
            throw new Error('No key pair found. Please, generate a key pair first');
        }
        const messageBuffer = Buffer.from(message);
        const signature = Buffer.alloc(sodium.crypto_sign_BYTES);
        sodium.crypto_sign_detached(signature, messageBuffer, this.#keyPair.secretKey);
        return signature;
    };

    exportToFile(filePath) {
        if (!this.#keyPair.secretKey) {
            throw new Error('No secret key found');
        }
        const data = {
            mnemonic: this.mnemonic,
            publicKey: this.#keyPair.publicKey.toString('hex'),
            secretKey: this.#keyPair.secretKey.toString('hex')
        };
        fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    }

    #sanitizeMnemonic(mnemonicInput) {
        if (!mnemonicInput) {
            return null;
        }
        const sanitized = mnemonicInput.toLowerCase().trim().split(' ').filter(word => word.trim()).join(' ');

        // Check if all words are valid
        const words = sanitized.split(' ');
        if (words.length !== 12 || !bip39.validateMnemonic(sanitized)) {
            throw new Error('Invalid mnemonic. Please, provide a valid 12-word mnemonic');
        }

        return sanitized;
    }
}