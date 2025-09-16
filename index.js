/** @typedef {import('pear-interface')} */
import fs from 'fs';
import readline from 'readline';
import tty from 'tty'
import b4a, { isBuffer } from 'b4a';
import { TRAC_NETWORK_MSB_MAINNET_PREFIX } from './constants.js';
import tracCryptoApi from 'trac-crypto-api';

class Wallet {
    #networkPrefix;
    #derivationPath;
    #keyPair;
    ready;

    /**
     * Creates a new Wallet instance.
     * @param {Object} options - Wallet options.
     * @param {string} [options.mnemonic] - Optional mnemonic phrase for key generation.
     * @param {string} [options.derivationPath] - Optional derivation path for key generation.
     * @param {string} [options.networkPrefix] - Optional network prefix for address encoding.
     */
    // Disclaimer: Please note that the function #initKeyPair is async. This means that the keypair is not set
    // until the function finishes executing. For most cases, this will be irrelevant, but it can lead to errors
    // if you try to access the keypair properties before the function has completed.
    // Always use await Wallet.ready before trying to access the keypair.
    constructor(options = {}) {
        this.#networkPrefix = options.networkPrefix || TRAC_NETWORK_MSB_MAINNET_PREFIX;
        this.#derivationPath = options.derivationPath || null;
        this.ready = this.#initKeyPair(options.mnemonic || null, this.#derivationPath);
    }

    /**
     * Gets the public key as a Buffer.
     * @returns {Buffer|null} The public key, or null if not set.
     */
    get publicKey() {
        return this.#keyPair.publicKey;
    }

    /**
     * Gets the secret key as a Buffer.
     * @returns {Buffer|null} The secret key, or null if not set.
     */
    get secretKey() {
        return this.#keyPair.secretKey;
    }

    /**
     * Gets the TRAC address for the wallet.
     * @returns {string|null} The Bech32m encoded address, or null if not set.
     */
    get address() {
        return this.#keyPair.address;
    }

    /**
     * Gets the derivation path for the wallet.
     * @returns {string|null} The derivation path, or null if not set.
     */
    get derivationPath() {
        return this.#keyPair.derivationPath;
    }

    /**
     * Generates a new key pair and address from a mnemonic.
     * If no mnemonic is provided, a new one is generated.
     * @param {string} [mnemonic] - Optional mnemonic phrase.
     * @returns {Promise<void>}
     */
    async generateKeyPair(mnemonic = null, derivationPath = null) {
        if (!mnemonic) {
            mnemonic = tracCryptoApi.mnemonic.generate();
        }
        await this.#initKeyPair(mnemonic, derivationPath);
    }

    /**
     * Signs a message with the provided private key.
     * @param {Buffer} message - The message to sign.
     * @param {Buffer} privateKey - The private key for signing.
     * @returns {Buffer} The signature as a Buffer, or empty Buffer on error.
     */
    static sign(message, privateKey) {
        return tracCryptoApi.sign(message, privateKey);
    }

    /**
     * Signs a message using the wallet's stored secret key.
     * @param {Buffer} message - The message to sign.
     * @returns {Buffer} The signature as a Buffer, or empty Buffer on error.
     */
    sign(message, privateKey = this.#keyPair.secretKey) {
        if (!privateKey) {
            console.error('No private key provided');
            return b4a.alloc(0);
        }
        return Wallet.sign(message, privateKey);
    }

    /**
     * Verifies a message signature.
     * @param {Buffer} signature - The signature to verify.
     * @param {Buffer} message - The message to verify.
     * @param {Buffer} publicKey - The public key to verify against.
     * @returns {boolean} True if valid, false otherwise.
     */
    static verify(signature, message, publicKey) {
        if (!b4a.isBuffer(signature) || signature.length !== tracCryptoApi.signature.SIZE) {
            console.error('Invalid signature');
            return false;
        }

        if (!b4a.isBuffer(message) || message.length === 0) {
            console.error('Invalid message');
            return false;
        }

        if (!b4a.isBuffer(publicKey) || publicKey.length !== tracCryptoApi.address.PUB_KEY_SIZE) {
            console.error('Invalid public key');
            return false;
        }

        try {
            return tracCryptoApi.signature.verify(signature, message, publicKey);
        } catch (e) { console.error(e) }
        return false;
    }

    /**
     * Verifies a signature using the wallet's public key.
     * @param {Buffer} signature - The signature to verify.
     * @param {Buffer} message - The message to verify.
     * @param {Buffer} publicKey - The public key to verify against. Defaults to stored public key
     * @returns {boolean} True if valid, false otherwise.
     */
    verify(signature, message, publicKey = this.#keyPair.publicKey) {
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
     * Sanitizes and validates a derivation path string.
     * Accepts BIP32/BIP44 style paths like m/44'/0'/0'/0'/0'.
     * All segments must be hardened (i.e., end with a prime symbol ').
     * Returns null if invalid.
     * @param {string} derivationPath - The derivation path to sanitize.
     * @returns {string|null} The sanitized derivation path, or null if invalid.
     */
    // TODO: Replace this implementation when a similar function is implemented in Trac Crypto Api
    sanitizeDerivationPath(derivationPath) {
        if (typeof derivationPath !== 'string') return null;
        const trimmed = derivationPath.trim();
        const bip32HardenedRegex = /^m(\/[0-9]+'?)+$/;
        if (!bip32HardenedRegex.test(trimmed)) return null;
        return trimmed;
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
            if (buffer.length !== tracCryptoApi.address.PUB_KEY_SIZE) {
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
            if (buffer.length !== tracCryptoApi.address.PRIV_KEY_SIZE) {
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
    exportToFile(filePath, password) {
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
            mnemonic: this.#keyPair.mnemonic,
            derivationPath: this.#keyPair.derivationPath
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
            fs.writeFileSync(filePath, fileData);
            console.log('Key pair exported to', filePath);
        } catch (err) {
            console.error('Error writing to file:', err);
        }
        finally {
            // Cleanup sensitive data from memory
            tracCryptoApi.utils.memzero(encrypted.nonce);
            tracCryptoApi.utils.memzero(encrypted.salt);
            tracCryptoApi.utils.memzero(encrypted.ciphertext);
        }
    }

    /**
     * Imports a key pair from an encrypted JSON file.
     * @param {string} filePath - Path to the file.
     * @param {Buffer} password - Buffer used for decryption.
     * @returns {Promise<void>}
     * @throws {Error} If required parameters are missing or invalid.
     */
    importFromFile(filePath, password) {
        if (!filePath) {
            throw new Error('File path is required');
        }

        if (!b4a.isBuffer(password) || password.length === 0) {
            throw new Error('Password must be a buffer with length greater than 0');
        }

        const fileData = this.#readFile(filePath);

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
    #readFile(path) {
        try {
            if (!fs.existsSync(path)) {
                throw new Error(`File ${path} not found`);
            }
            return JSON.parse(fs.readFileSync(path, 'utf8'));
        } catch (err) {
            throw new Error('Error reading file: ' + err.message);
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

        // Convert obtained data to a keypair object
        const decryptedBuf = tracCryptoApi.data.decrypt(encrypted, password);
        const decrypted = JSON.parse(decryptedBuf.toString('utf8'));
        decrypted.publicKey = this.sanitizePublicKey(decrypted.publicKey);
        decrypted.secretKey = this.sanitizeSecretKey(decrypted.secretKey);
        decrypted.mnemonic = this.sanitizeMnemonic(decrypted.mnemonic);
        decrypted.derivationPath = this.sanitizeDerivationPath(decrypted.derivationPath);

        // Cleanup sensitive data from memory
        tracCryptoApi.utils.memzero(encrypted.salt);
        tracCryptoApi.utils.memzero(encrypted.nonce);
        tracCryptoApi.utils.memzero(encrypted.ciphertext);

        return decrypted;
    }

    /**
     * Fills the keypair data from the provided object.
     * @param {Object} data - Keypair data containing sanitized publicKey, secretKey in Buffer format 
     *                        and mnemonic, derivationPath in string format.
     * @private
     */
    #fillKeypairData(data) {
        this.#keyPair.publicKey = data.publicKey;
        this.#keyPair.secretKey = data.secretKey;
        this.#keyPair.mnemonic = data.mnemonic;
        this.#keyPair.derivationPath = data.derivationPath;
        this.#keyPair.address = tracCryptoApi.address.encode(this.#networkPrefix, data.publicKey);
    }

    /**
     * Initializes the wallet key pair and address from a mnemonic.
     * If no mnemonic is provided, all values are set to null.
     * @param {string|null} mnemonic - Optional mnemonic phrase.
     * @param {string|null} derivationPath - Optional derivation path.
     * @returns {Promise<void>}
     * @private
     */
    async #initKeyPair(mnemonic = null, derivationPath = null) {
        if (mnemonic) {
            try {
                // TODO: Currently trac-crypto-api crashes when derivation path is null, so we pass undefined instead.
                // Once the issue is fixed, we can revert this change.
                const kp = await tracCryptoApi.address.generate(this.#networkPrefix, mnemonic, derivationPath ?? undefined);
                if (kp && kp.publicKey && kp.secretKey && kp.mnemonic && kp.address && kp.derivationPath) {
                    this.#keyPair = {
                        publicKey: kp.publicKey,
                        secretKey: kp.secretKey,
                        mnemonic: kp.mnemonic,
                        address: kp.address,
                        derivationPath: kp.derivationPath
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
            derivationPath: null
        };
    }

    //------------------- Trac Crypto API exposure functions -------------------//
    // The functions below are implemented here for convenience, so users of the Wallet class
    // can access the API functions without needing to import trac-crypto-api separately.

    /**
     * Decodes a Bech32m encoded address string into its raw form.
     * @param {string} address - The Bech32m encoded address to decode.
     * @returns {Buffer} The decoded address as a Buffer.
     */
    static decodeBech32m(address) {
        return tracCryptoApi.address.decode(address);
    }

    /**
     * Safely decodes a Bech32m encoded address string. Returns null on error.
     * @param {string} address - The Bech32m encoded address to decode.
     * @returns {Buffer|null} The decoded address as a Buffer, or null if decoding fails.
     */
    static decodeBech32mSafe(address) {
        try {
            return tracCryptoApi.address.decode(address);
        } catch (e) {
            console.error('Error decoding address:', e.message);
            return null;
        }
    }

    /**
     * Generates a cryptographically secure random nonce.
     * @returns {Buffer} The generated nonce as a Buffer.
     */
    static generateNonce() {
        return tracCryptoApi.nonce.generate();
    }

    /**
     * Encodes a public key Buffer into a Bech32m address string.
     * @param {string} hrp - The human-readable part (prefix) for the address.
     * @param {Buffer} publicKey - The public key to encode.
     * @returns {string} The Bech32m encoded address string.
     */
    static encodeBech32m(hrp, publicKey) {
        return tracCryptoApi.address.encode(hrp, publicKey);
    }

    /**
     * Safely encodes a public key Buffer into a Bech32m address string. Returns null on error.
     * @param {string} hrp - The human-readable part (prefix) for the address.
     * @param {Buffer} publicKey - The public key to encode.
     * @returns {string|null} The Bech32m encoded address string, or null if encoding fails.
     */
    static encodeBech32mSafe(hrp, publicKey) {
        try {
            return tracCryptoApi.address.encode(hrp, publicKey);
        } catch (e) {
            console.error('Error encoding address:', e.message);
            return null;
        }
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
                        console.log("Key pair generated and stored in", filePath);
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