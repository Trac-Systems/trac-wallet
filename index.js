/** @typedef {import('pear-interface')} */
import { generateMnemonic, validateMnemonic, mnemonicToSeed } from 'bip39-mnemonic';
import sodium from 'sodium-native';
import fs from 'fs';
import readline from 'readline';
import tty from 'tty'
import b4a from 'b4a';

const RANDOM_BUFFER_SIZE = 32;
class Wallet {
    #keyPair;
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
        try{
            const signatureBuffer = b4a.isBuffer(signature) ? signature : b4a.from(signature, 'hex');
            const messageBuffer = b4a.isBuffer(message) ? message : b4a.from(message);
            const publicKeyBuffer = b4a.isBuffer(publicKey) ? publicKey : b4a.from(publicKey, 'hex');
            return sodium.crypto_sign_verify_detached(signatureBuffer, messageBuffer, publicKeyBuffer);
        } catch(e) { console.log(e) }
        return false;
    }

    /**
     * Generates a new mnemonic phrase.
     * @returns {string} A new mnemonic phrase.
     */
    generateMnemonic() {
        return generateMnemonic();
    }

    async createHash(type, message){
        if(type === 'sha256'){
            const out = b4a.alloc(sodium.crypto_hash_sha256_BYTES);
            sodium.crypto_hash_sha256(out, b4a.from(message));
            return b4a.toString(out, 'hex');
        }
        let createHash = null;
        if(global.Pear !== undefined){
            let _type = '';
            switch(type.toLowerCase()){
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
        } else {
            return crypto.createHash(type).update(message).digest('hex')
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
    exportToFile(filePath, mnemonic = null) {
        if (!this.#keyPair.secretKey) {
            throw new Error('No key pair found');
        }
        const data = {
            publicKey: this.#keyPair.publicKey.toString('hex'),
            secretKey: this.#keyPair.secretKey.toString('hex')
        };
        if(mnemonic !== null ){
            data['mnemonic'] = mnemonic;
        }
        fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    }

    /**
     * Imports a key pair from a JSON file. If the wallet is set to verifyOnly mode, it will return to standard mode
     * @param {string} filePath - The path to the file where the keys are saved.
     * @throws Will throw an error if the wallet is set to verify only.
     */
    importFromFile(filePath) {
        if (this.#isVerifyOnly) {
            throw new Error('This wallet is set to verify only. Please create a new wallet instance with a valid mnemonic to generate a key pair');
        }
        const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
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
        if((global.Pear !== undefined && global.Pear.config.options.type === 'terminal') || global.Pear === undefined){
            let rl;
            if(readline_instance !== null){
                rl = readline_instance;
            } else {
                rl = readline.createInterface({
                    input: new tty.ReadStream(0),
                    output: new tty.WriteStream(1)
                });
            }
            let response;
            let choice = '';
            console.log("\n[1]. Generate new mnemonic phrase\n",
                "[2]. Restore keypair from 24-word phrase\n",
                "[3]. Input a keypair manually\n",
                "[4]. Import keypair from file\n",
                "Your choice(1/ 2/ 3/ 4/):"
            );
            let choiceFunc = async function(input){
                choice = input;
            }
            rl.on('line', choiceFunc);
            while('' === choice){
                await this.sleep(1000);
            }
            rl.off('line', choiceFunc);
            try{
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
                        let mnem = async function(input){
                            mnemonicInput = input;
                        };
                        rl.on('line', mnem);
                        while('' === mnemonicInput){
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
                        let pubkey = async function(input){
                            publicKey = input;
                        }
                        console.log("Enter your public key:");
                        rl.on('line', pubkey);
                        while('' === publicKey){
                            await this.sleep(1000);
                        }
                        rl.off('line', pubkey);
                        console.log("Enter your secret key:");
                        let secretKey = '';
                        let seckey = async function(input){
                            secretKey = input;
                        };
                        rl.on('line', seckey);
                        while('' === secretKey){
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
                        let fpath = async function(input){
                            filePath = input;
                        };
                        rl.on('line', fpath);
                        while('' === filePath){
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
            } catch(e) {
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

    async sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

export default PeerWallet;