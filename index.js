/** @typedef {import('pear-interface')} */
import { generateMnemonic, validateMnemonic, mnemonicToSeed } from 'bip39-mnemonic';
import sodium from 'sodium-native';
import fs from 'fs';
import readline from 'readline';
import tty from 'tty'
import b4a from 'b4a';
import { RANDOM_BUFFER_SIZE, ENCRYPTION_KEY_BYTES } from './constants.js';

class Wallet {
    #keyPair;
    #isVerifyOnly;
    #address;
    #tracNetworkMainnetPrefix = 0x01;

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
            this.generateKeyPair(options.mnemonic);
        }

        this.networkPrefix = options.networkPrefix || this.#tracNetworkMainnetPrefix;
        this.#address = this.#setupTracAddress();
    }

    /**
     * Returns the public key as a hex string.
     * @returns {string|null} The public key in hex format or null if not set.
     */
    get publicKey() {
        if (!this.#keyPair.publicKey) {
            return null;
        }
        return this.#keyPair.publicKey;
    }

    /**
     * Returns the secret key as a hex string.
     * @returns {string|null} The secret key in hex format or null if not set.
     */
    get secretKey() {
        if (!this.#keyPair.secretKey) {
            return null;
        }
        return this.#keyPair.secretKey;
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
     * Returns the TRAC address for the wallet.
     * If the public key is not set, returns null.
     * If the address has not been generated yet, it will be created by calling #setupTracAddress().
     * @returns {Buffer|null} The TRAC address as a Buffer, or null if the public key is not set.
     */
    get address() {
        if (!this.#keyPair.publicKey) {
            return null;
        }

        if (!this.#address) {
            this.#setupTracAddress();
        }

        return this.#address;
    }

    /**
     * Sets up the TRAC address for the wallet by concatenating the network prefix and the public key.
     * The address is stored in the private #address property.
     * If an error occurs (e.g., publicKey is not set), the address will be set to null.
     * 
     * @private
     */
    #setupTracAddress() {
        const assembleAddress = () => {
            try {
                return b4a.concat([b4a.alloc(1, this.networkPrefix), this.publicKey]);
            }
            catch {
                return null;
            }
        };
        this.#address = assembleAddress();
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
        return generateMnemonic();
    }

    /**
     * Creates a hash of the given message using the specified algorithm.
     * @param {string} type - The hash algorithm to use (e.g., 'sha256', 'sha1', 'sha384', 'sha512').
     * @param {string} message - The message to hash.
     * @returns {string} The hash in hex format.
    */
    // TODO: Refactor / improve security for this function
    async createHash(type, message) {
        if (type === 'sha256') {
            const out = b4a.alloc(sodium.crypto_hash_sha256_BYTES);
            sodium.crypto_hash_sha256(out, b4a.from(message));
            return out;
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
            const hashArray = b4a.from(new Uint8Array(hash));
            return hashArray;
        } else {
            return b4a.from(crypto.createHash(type).update(message).digest('hex'), 'hex'); // TODO: Implement tests for this part of the code
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
        return signature;
    }

    /**
     * Encrypts the exported key file data
     * @param {Buffer} data - The data to encrypt.
     * @param {Buffer} key - A 32-byte encryption key.
     * @returns {Object} The encrypted data as JSON containing nonce and cyphertext.
     */
    encrypt(data, key) {
        if (!b4a.isBuffer(key) || key.length !== ENCRYPTION_KEY_BYTES) {
            throw new Error(`Key must be a ${ENCRYPTION_KEY_BYTES} bytes long buffer`);
        }

        if (!b4a.isBuffer(data)) {
            throw new Error('Data must be a Buffer');
        }

        const nonce = b4a.alloc(sodium.crypto_secretbox_NONCEBYTES);
        sodium.randombytes_buf(nonce);
        const ciphertext = b4a.alloc(data.length + sodium.crypto_secretbox_MACBYTES);
        sodium.crypto_secretbox_easy(ciphertext, data, nonce, key);

        const returnData = {
            nonce: nonce.toString('hex'),
            ciphertext: ciphertext.toString('hex')
        };

        // Cleanup sensitive data from memory
        sodium.sodium_memzero(nonce);
        sodium.sodium_memzero(ciphertext);

        return returnData;
    }

    /**
     * Decrypts the encrypted key file data using sodium-native.
     * @param {string|Object} encryptedData - The encrypted data as a JSON string or an object.
     * @param {Buffer} key - A 32-byte decryption key.
     * @returns {Object} The decrypted JSON containing the key pair.
     * @throws Will throw an error if decryption fails.
     */
    decrypt(encryptedData, key) {
        if (key.length !== ENCRYPTION_KEY_BYTES) {
            throw new Error(`Key must be ${ENCRYPTION_KEY_BYTES} bytes long`);
        }

        const data = typeof encryptedData === 'string' ? JSON.parse(encryptedData) : encryptedData;

        if (!data.nonce || !data.ciphertext) {
            throw new Error('Invalid encrypted data format. Missing nonce or ciphertext.');
        }

        const nonceBuffer = b4a.from(data.nonce, 'hex');
        const ciphertextBuffer = b4a.from(data.ciphertext, 'hex');
        const messageBuffer = b4a.alloc(ciphertextBuffer.length - sodium.crypto_secretbox_MACBYTES);

        if (!sodium.crypto_secretbox_open_easy(messageBuffer, ciphertextBuffer, nonceBuffer, key)) {
            throw new Error('Failed to decrypt data. Invalid key or corrupted data.');
        }

        const returnData = JSON.parse(messageBuffer.toString('utf8'));

        // Cleanup sensitive data from memory
        sodium.sodium_memzero(nonceBuffer);
        sodium.sodium_memzero(ciphertextBuffer);
        sodium.sodium_memzero(messageBuffer);

        return returnData;
    }

    /**
     * Derives a key from the password and salt using Argon2i.
     * @param {Buffer} password - The password to derive the key from.
     * @param {Buffer} salt - The salt to use for key derivation.
     * @returns {Buffer} The derived key.
     */
    #deriveKey(password, salt) {
        if (!b4a.isBuffer(password) || !b4a.isBuffer(salt)) {
            throw new Error('Password and salt must be buffers');
        }

        const key = b4a.alloc(ENCRYPTION_KEY_BYTES);
        sodium.crypto_pwhash(
            key,
            password,
            salt,
            sodium.crypto_pwhash_OPSLIMIT_MODERATE,
            sodium.crypto_pwhash_MEMLIMIT_MODERATE,
            sodium.crypto_pwhash_ALG_ARGON2I13
        );

        return key;
    }

    /**
     * Exports the key pair to a JSON file.
     * @param {string} filePath - The path to the file where the keys will be saved.
     * @param {string} [mnemonic=null] - The mnemonic phrase to include in the file. If null, it will not be included.
     * @param {Buffer|null} [encryptionKey=""] - The encryption key to use for encrypting the file. If not provided, the file will not be encrypted.
     * @throws Will throw an error if the key pair is not set.
     */
    exportToFile(filePath, mnemonic = null, encryptionKey = null) { // TODO: In the future, the encryptionKey parameter should not be optional!
        if (!this.#keyPair.secretKey) {
            throw new Error('No key pair found');
        }

        let fileData = "";
        let key = null;
        let salt = null;
        let shouldEncrypt = false; // TODO: This is just a temporary solution for backward compatibility. In the future, the encryption will be mandatory

        if (!b4a.isBuffer(encryptionKey) && encryptionKey !== null) {
            throw new Error('Encryption key must either be a buffer or null');
        }

        if (encryptionKey) {
            shouldEncrypt = true;
        }

        const data = {
            publicKey: this.#keyPair.publicKey.toString('hex'),
            secretKey: this.#keyPair.secretKey.toString('hex')
        };

        const safeMnemonic = this.sanitizeMnemonic(mnemonic);
        if (safeMnemonic !== null) {
            data['mnemonic'] = safeMnemonic;
        }

        const message = JSON.stringify(data, null, 2);

        if (!shouldEncrypt) {
            fileData = message;
        } else {
            salt = b4a.alloc(sodium.crypto_pwhash_SALTBYTES);
            sodium.randombytes_buf(salt);
            key = this.#deriveKey(encryptionKey, salt);

            const msgBuf = b4a.from(message, 'utf8');
            const fdata = this.encrypt(msgBuf, key);
            fdata.salt = salt.toString('hex');
            fileData = JSON.stringify(fdata, null, 2);
        }

        try {
            fs.writeFileSync(filePath, fileData);
            console.log('Key pair exported to', filePath);
        } catch (err) {
            console.error('Error writing to file:', err);
        }
        finally {
            // Cleanup sensitive data from memory
            if (shouldEncrypt) {
                sodium.sodium_memzero(key);
                sodium.sodium_memzero(salt);
            }
        }
    }

    /**
     * Imports a key pair from a JSON file. If the wallet is set to verifyOnly mode, it will return to standard mode
     * @param {string} filePath - The path to the file where the keys are saved.
     * @param {Buffer|null} [encryptionKey=""] - The encryption key to use for decrypting the file. If not provided, the function assumes the file is not encrypted.
     * @throws Will throw an error if the wallet is set to verify only.
     */
    importFromFile(filePath, encryptionKey = null) { // TODO: In the future, the key parameter should not be optional!
        if (this.#isVerifyOnly) {
            throw new Error('This wallet is set to verify only. Please create a new wallet instance with a valid mnemonic to generate a key pair');
        }

        let data;
        try {
            if (!fs.existsSync(filePath)) {
                throw new Error(`File ${filePath} not found`);
            }
            data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        } catch (err) {
            throw new Error('Error importing file:', err);
        }

        if (encryptionKey !== null) {
            if (!data.salt || !data.nonce || !data.ciphertext) {
                throw new Error('Could not decrypt keyfile. Data is invalid or corrupted');
            }

            const salt = b4a.from(data.salt, 'hex');
            const key = this.#deriveKey(encryptionKey, salt);

            data = this.decrypt(data, key);

            // Cleanup sensitive data from memory
            sodium.sodium_memzero(key);
            sodium.sodium_memzero(salt);
        }
        this.#keyPair = this.sanitizeKeyPair(data.publicKey, data.secretKey);
        this.#isVerifyOnly = false;
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
        if (!validateMnemonic(sanitized)) {
            throw new Error('Invalid mnemonic phrase');
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
    /**
     * Generates a random nonce with high entrophy.
     * 
     * @returns {Buffer} A securely generated 32-byte nonce as a Buffer.
     */
    static generateNonce() {
        const nonce = b4a.alloc(RANDOM_BUFFER_SIZE);
        sodium.randombytes_buf(nonce);
        return nonce;
    }
}

class PeerWallet extends Wallet {
    #isVerifyOnly;
    #readlineInstance = null;

    constructor(options = {}) {
        super(options);
        this.#isVerifyOnly = options.isVerifyOnly || false;
    }

    async initKeyPair(filePath, readline_instance = null) {
        if (this.#isVerifyOnly) {
            throw new Error('This wallet is set to verify only. Please create a new wallet instance with a valid mnemonic to generate a key pair');
        }

        if (!filePath) {
            throw new Error("File path is required");
        }

        try {
            if (fs.existsSync(filePath)) {
                const keyPair = JSON.parse(fs.readFileSync(filePath));
                this.keyPair = {
                    publicKey: keyPair.publicKey,
                    secretKey: keyPair.secretKey
                }
            } else {
                console.log("Key file was not found. How do you wish to proceed?");
                const response = await this.#setupKeypairInteractiveMode(readline_instance);
                switch (response.type) {
                    case 'keypair':
                        this.keyPair = response.value;
                        break;
                    case 'mnemonic':
                        let mnemonic = response.value;
                        if (mnemonic === null) {
                            mnemonic = this.generateMnemonic();
                            console.log("This is your mnemonic:\n", mnemonic, "\nPlease back it up in a safe location")
                        }
                        await this.generateKeyPair(mnemonic);
                        this.exportToFile(filePath, mnemonic);
                        console.log("DEBUG: Key pair generated and stored in", filePath);
                        break;
                    case 'import':
                        this.importFromFile(response.value);
                        break;
                    default:
                        console.error("Invalid response type from keypair setup interactive menu");
                }
            }
        } catch (err) {
            console.error(err);
        }
    }

    async #setupKeypairInteractiveMode(readline_instance = null) {
        if ((global.Pear !== undefined && global.Pear.config.options.type === 'terminal') || global.Pear === undefined) {
            let rl;
            if (readline_instance !== null) {
                rl = readline_instance;
            } else {
                rl = readline.createInterface({
                    input: new tty.ReadStream(0),
                    output: new tty.WriteStream(1)
                });
            }
            if (this.#readlineInstance != null) {
                await this.#readlineInstance.close();
            }
            this.#readlineInstance = rl;
            let response;
            let choice = '';
            console.log("\n[1]. Generate new mnemonic phrase\n",
                "[2]. Restore keypair from 24-word phrase\n",
                "[3]. Input a keypair manually\n",
                "[4]. Import keypair from file\n",
                "Your choice(1/ 2/ 3/ 4/):"
            );
            let choiceFunc = async function (input) {
                choice = input;
            }
            rl.on('line', choiceFunc);
            while ('' === choice) {
                await this.sleep(1000);
            }
            rl.off('line', choiceFunc);
            try {
                switch (choice) {
                    case '1':
                        response = {
                            type: 'mnemonic',
                            value: null
                        }
                        break;
                    case '2':
                        console.log("Enter your mnemonic phrase:");
                        let mnemonicInput = '';
                        let mnem = async function (input) {
                            mnemonicInput = input;
                        };
                        rl.on('line', mnem);
                        while ('' === mnemonicInput) {
                            await this.sleep(1000);
                        }
                        rl.off('line', mnem);
                        response = {
                            type: 'mnemonic',
                            value: this.sanitizeMnemonic(mnemonicInput.trim())
                        }
                        break;
                    case '3':
                        let publicKey = '';
                        let pubkey = async function (input) {
                            publicKey = input;
                        }
                        console.log("Enter your public key:");
                        rl.on('line', pubkey);
                        while ('' === publicKey) {
                            await this.sleep(1000);
                        }
                        rl.off('line', pubkey);
                        console.log("Enter your secret key:");
                        let secretKey = '';
                        let seckey = async function (input) {
                            secretKey = input;
                        };
                        rl.on('line', seckey);
                        while ('' === secretKey) {
                            await this.sleep(1000);
                        }
                        rl.off('line', seckey);
                        response = {
                            type: 'keypair',
                            value: {
                                publicKey: publicKey.trim(),
                                secretKey: secretKey.trim()
                            }
                        }
                        break;
                    case '4':
                        console.log("Enter the path to the keypair file:");
                        let filePath = '';
                        let fpath = async function (input) {
                            filePath = input;
                        };
                        rl.on('line', fpath);
                        while ('' === filePath) {
                            await this.sleep(1000);
                        }
                        rl.off('line', fpath);
                        response = {
                            type: 'import',
                            value: filePath.trim()
                        }
                        break;
                    default:
                        console.log("Invalid choice. Please select again.");
                        response = null;
                        choice = '';
                        return this.#setupKeypairInteractiveMode(readline_instance);
                }
            } catch (e) {
                console.log("Invalid input. Please try again.");
                response = null;
                choice = '';
                return this.#setupKeypairInteractiveMode(readline_instance);
            }
            if (this.#readlineInstance !== null) {
                await this.#readlineInstance.close();
            }
            return response;
        }
        // desktop mode if pear
        return {
            type: 'mnemonic',
            value: null
        };
    }

    async close() {
        if (this.#readlineInstance !== null) {
            await this.#readlineInstance.close();
        }
    }

    async sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

export default PeerWallet;