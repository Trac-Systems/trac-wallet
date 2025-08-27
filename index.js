/** @typedef {import('pear-interface')} */
// import { fs, fsReady } from './fs-provider.js';
import fs from 'fs';
import readline from 'readline';
import tty from 'tty'
import b4a, { isBuffer } from 'b4a';
import { TRAC_NETWORK_MSB_MAINNET_PREFIX } from './constants.js';
import tracCryptoApi from 'trac-crypto-api';

class Wallet {
    #networkPrefix;
    #keyPair;

    /**
     * Creates a new Wallet instance.
     * @param {Object} options - Wallet options.
     * @param {string} [options.mnemonic] - Optional mnemonic phrase for key generation.
     * @param {string} [options.networkPrefix] - Optional network prefix for address encoding.
     */
    constructor(options = {}) {
        this.#networkPrefix = options.networkPrefix || TRAC_NETWORK_MSB_MAINNET_PREFIX;
        this.#initKeyPair(options.mnemonic || null);
    }

    /**
     * Gets the public key as a Buffer.
     * @returns {Buffer|null} The public key, or null if not set.
     */
    get publicKey() {
        return this.#keyPair.publicKey || null;
    }

    /**
     * Gets the secret key as a Buffer.
     * @returns {Buffer|null} The secret key, or null if not set.
     */
    get secretKey() {
        return this.#keyPair.secretKey || null;
    }

    /**
     * Gets the TRAC address for the wallet.
     * @returns {string|null} The Bech32m encoded address, or null if not set.
     */
    get address() {
        return this.#keyPair.address || null;
    }

    /**
     * Generates a new key pair and address from a mnemonic.
     * If no mnemonic is provided, a new one is generated.
     * @param {string} [mnemonic] - Optional mnemonic phrase.
     * @returns {Promise<void>}
     */
    async generateKeyPair(mnemonic = null) {
        if (!mnemonic) {
            mnemonic = tracCryptoApi.mnemonic.generate();
        }
        await this.#initKeyPair(mnemonic);
    }

    /**
     * Signs a message with the provided private key.
     * @param {Buffer} message - The message to sign.
     * @param {Buffer} privateKey - The private key for signing.
     * @returns {Buffer} The signature as a Buffer, or empty Buffer on error.
     */
    static sign(message, privateKey) {
        if (!b4a.isBuffer(message)) {
            console.error('Message is required');
            return b4a.alloc(0);
        }

        if (!privateKey) {
            console.error('No private key provided');
            return b4a.alloc(0);
        }

        tracCryptoApi.sign(message, privateKey);
    }

    /**
     * Signs a message using the wallet's stored secret key.
     * @param {Buffer} message - The message to sign.
     * @returns {Buffer} The signature as a Buffer, or empty Buffer on error.
     */
    sign(message) {
        if (!this.#keyPair.secretKey) {
            console.error('No private key stored');
            return b4a.alloc(0);
        }
        return this.constructor.sign(message, this.#keyPair.secretKey);
    }

    /**
     * Verifies a message signature.
     * @param {Buffer|string} signature - The signature to verify.
     * @param {Buffer|string} message - The message to verify.
     * @param {Buffer|string} publicKey - The public key to verify against.
     * @returns {boolean} True if valid, false otherwise.
     */
    static verify(signature, message, publicKey) {
        try {
            const signatureBuffer = b4a.isBuffer(signature) ? signature : b4a.from(signature, 'hex');
            const messageBuffer = b4a.isBuffer(message) ? message : b4a.from(message);
            const publicKeyBuffer = b4a.isBuffer(publicKey) ? publicKey : b4a.from(publicKey, 'hex');
            return sodium.crypto_sign_verify_detached(signatureBuffer, messageBuffer, publicKeyBuffer);
        } catch (e) { console.log(e) }
        return false;
    }

    /**
     * Verifies a signature using the wallet's public key.
     * @param {Buffer|string} signature - The signature to verify.
     * @param {Buffer|string} message - The message to verify.
     * @param {Buffer|string} publicKey - The public key to verify against.
     * @returns {boolean} True if valid, false otherwise.
     */
    verify(signature, message, publicKey) {
        return Wallet.verify(signature, message, publicKey);
    }

    /**
     * Sanitizes and validates a mnemonic phrase.
     * @param {string} mnemonic - The mnemonic phrase.
     * @returns {string|null} The sanitized mnemonic, or null if invalid.
     */
    sanitizeMnemonic(mnemonic) {
        return tracCryptoApi.mnemonic.sanitize(mnemonic);
    }

    /**
     * Sanitizes and validates a public key.
     * @param {string} publicKey - The public key in hex format.
     * @returns {Buffer} The sanitized public key as a Buffer.
     * @throws {Error} If the public key is invalid.
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
     * @returns {Buffer} The sanitized secret key as a Buffer.
     * @throws {Error} If the secret key is invalid.
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
     * Exports the key pair to an encrypted JSON file.
     * @param {string} filePath - Path to save the file.
     * @param {Buffer} password - Buffer used for encryption.
     * @returns {Promise<void>}
     * @throws {Error} If required parameters are missing or invalid.
     */
    async exportToFile(filePath, password) {
        if (!filePath) {
            throw new Error('File path is required');
        }

        if (!b4a.isBuffer(password) || password.length === 0) {
            throw new Error('Password must be a buffer');
        }

        if (!this.#keyPair.secretKey) {
            throw new Error('No key pair stored');
        }

        const data = {
            publicKey: this.#keyPair.publicKey.toString('hex'),
            secretKey: this.#keyPair.secretKey.toString('hex'),
            mnemonic: this.#keyPair.mnemonic
        };

        const message = JSON.stringify(data, null, 2);
        const msgBuf = b4a.from(message, 'utf8');

        const encrypted = tracCryptoApi.data.encrypt(msgBuf, password)

        const fileData = JSON.stringify({
            nonce: encrypted.nonce.toString('hex'),
            salt: encrypted.salt.toString('hex'),
            ciphertext: encrypted.ciphertext.toString('hex')
        });

        try {
            await fsReady;
            fs.writeFileSync(filePath, fileData);
            console.log('Key pair exported to', filePath);
        } catch (err) {
            console.error('Error writing to file:', err);
        }
        finally {
            // Cleanup sensitive data from memory
            sodium.sodium_memzero(encrypted.nonce);
            sodium.sodium_memzero(encrypted.salt);
            sodium.sodium_memzero(encrypted.ciphertext);
        }
    }

    /**
     * Imports a key pair from an encrypted JSON file.
     * @param {string} filePath - Path to the file.
     * @param {Buffer} password - Buffer used for decryption.
     * @returns {Promise<void>}
     * @throws {Error} If required parameters are missing or invalid.
     */
    async importFromFile(filePath, password) {
        if (!filePath) {
            throw new Error('File path is required');
        }

        if (!b4a.isBuffer(password) || password.length === 0) {
            throw new Error('Password is required');
        }

        const fileData = await this.#readFile(filePath);

        if (!fileData.salt || !fileData.nonce || !fileData.ciphertext) {
            throw new Error('Could not decrypt keyfile. Data is invalid or corrupted');
        }

        const decrypted = this.#decryptKeystore(fileData, password);

        if (!isBuffer(decrypted.publicKey) || !isBuffer(decrypted.secretKey)) {
            throw new Error('Decrypted data does not contain valid keys');
        }

        this.#fillKeypairData(decrypted);
    }

    /**
     * Reads and parses a JSON file from disk.
     * @param {string} path - Path to the file.
     * @returns {Promise<Object>} Parsed file data as an object.
     * @throws {Error} If the file cannot be read or parsed.
     * @private
     */
    async #readFile(path) {
        try {
            await fsReady;
            if (!fs.existsSync(path)) {
                throw new Error(`File ${path} not found`);
            }
            return JSON.parse(fs.readFileSync(path, 'utf8'));
        } catch (err) {
            throw new Error('Error reading file:', err);
        }
    }

    /**
     * Decrypts the keystore data using the provided password.
     * @param {Object} fileData - Encrypted file data containing salt, nonce, and ciphertext (hex strings).
     * @param {Buffer} password - Buffer used for decryption.
     * @returns {Object} Decrypted keypair data.
     * @private
     */
    #decryptKeystore(fileData, password) {
        const encrypted = {
            salt: b4a.from(fileData.salt, 'hex'),
            nonce: b4a.from(fileData.nonce, 'hex'),
            ciphertext: b4a.from(fileData.ciphertext, 'hex')
        }

        const decrypted = tracCryptoApi.data.decrypt(encrypted, password);

        // Cleanup sensitive data from memory
        sodium.sodium_memzero(encrypted.salt);
        sodium.sodium_memzero(encrypted.nonce);
        sodium.sodium_memzero(encrypted.ciphertext);

        return decrypted;
    }

    /**
     * Fills the keypair data from the provided object.
     * @param {Object} data - Keypair data containing publicKey, secretKey, mnemonic in Buffer format.
     * @private
     */
    #fillKeypairData(data) {
        this.#keyPair.publicKey = this.sanitizePublicKey(data.publicKey);
        this.#keyPair.secretKey = this.sanitizeSecretKey(data.secretKey);
        this.#keyPair.mnemonic = this.sanitizeMnemonic(data.mnemonic);
        this.#keyPair.address = tracCryptoApi.address.encode(this.#networkPrefix, data.publicKey);
    }

    /**
     * Initializes the wallet key pair and address from a mnemonic.
     * If no mnemonic is provided, all values are set to null.
     * @param {string|null} mnemonic - Optional mnemonic phrase.
     * @returns {Promise<void>}
     * @private
     */
    async #initKeyPair(mnemonic = null) {
        console.log('Initializing key pair... Mnemonic = ', mnemonic);
        if (mnemonic) {
            try {
                const kp = await tracCryptoApi.address.generate(this.#networkPrefix, mnemonic);
                if (kp && kp.publicKey && kp.secretKey && kp.mnemonic && kp.address) {
                    this.#keyPair = {
                        publicKey: kp.publicKey,
                        secretKey: kp.secretKey,
                        mnemonic: kp.mnemonic,
                        address: kp.address
                    };
                    return;
                } else {
                    throw new Error('Invalid keypair generated');
                }
            }
            catch (e) {
                throw new Error('Error initializing keypair: ' + e.message);
            }
        }
        // If no mnemonic was provided, set all values to null
        this.#keyPair = {
            address: null,
            publicKey: null,
            secretKey: null,
            mnemonic: null,
        };
    }
}

class PeerWallet extends Wallet {
    #readlineInstance = null;

    /**
     * Creates a new PeerWallet instance.
     * @param {Object} options - Wallet options.
     */
    constructor(options = {}) {
        super(options);
    }

    /**
     * Initializes the keypair from a file or interactively if not found.
     * @param {string} filePath - Path to the keypair file.
     * @param {readline.Interface|null} [readline_instance] - Optional readline instance for interactive mode.
     * @returns {Promise<void>}
     */
    async initKeyPair(filePath, readline_instance = null) {
        if (!filePath) {
            throw new Error("File path is required");
        }
        try {
            await fsReady;
            if (fs.existsSync(filePath)) {
                // TODO: Fix. There is no unencrypted keyfile anymore
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
                        await this.exportToFile(filePath, mnemonic);
                        console.log("DEBUG: Key pair generated and stored in", filePath);
                        break;
                    case 'import':
                        await this.importFromFile(response.value);
                        break;
                    default:
                        console.error("Invalid response type from keypair setup interactive menu");
                }
            }
        } catch (err) {
            console.error(err);
        }
    }

    /**
     * Interactive setup for keypair creation or import.
     * @param {readline.Interface|null} [readline_instance] - Optional readline instance.
     * @returns {Promise<Object>} Response object with type and value.
     * @private
     */
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
                await this.#sleep(1000);
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
                            await this.#sleep(1000);
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
                            await this.#sleep(1000);
                        }
                        rl.off('line', pubkey);
                        console.log("Enter your secret key:");
                        let secretKey = '';
                        let seckey = async function (input) {
                            secretKey = input;
                        };
                        rl.on('line', seckey);
                        while ('' === secretKey) {
                            await this.#sleep(1000);
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
                            await this.#sleep(1000);
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
            return response;
        }
        // desktop mode if pear
        return {
            type: 'mnemonic',
            value: null
        };
    }

    /**
     * Closes the readline instance if open.
     * @returns {Promise<void>}
     */
    async close() {
        if (this.#readlineInstance !== null) {
            await this.#readlineInstance.close();
        }
    }

    /**
     * Sleeps for the specified milliseconds.
     * @param {number} ms - Milliseconds to sleep.
     * @returns {Promise<void>}
     */
    async #sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

export default PeerWallet;