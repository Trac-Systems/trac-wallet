/** @typedef {import('pear-interface')} */
import fs from 'fs';
import { IHDWallet, IWallet } from "./types/index.ts";
import b4a from 'b4a';
import * as tracCryptoApi from 'trac-crypto-api'
import { CURRENT_VERSION, WalletProvider } from './wallet.ts';

const ensureWalletIntegrity = (wallet: IWallet | IHDWallet, publicKey?: string) => {
    if (!publicKey) {
        return;
    }

    const importedPublicKey = b4a.from(publicKey, 'hex');
    if (!b4a.equals(wallet.publicKey, importedPublicKey)) {
        throw new Error('Imported keystore publicKey does not match the derived wallet');
    }
}

const ensureSupportedVersion = (version?: unknown) => {
    // This is here right now to ensure BC with the lib 1.0.x
    if (version !== CURRENT_VERSION && version !== undefined) {
        throw new Error('Imported keystore version is not supported');
    }
}

const toWallet = async (params, hrp?: string) => {
    ensureSupportedVersion(params.version);

    const addressPrefix = params.addressPrefix ?? hrp;

    if (!addressPrefix) {
        throw new Error('Imported keystore is incompatible with this wallet version');
    }

    if (params.mnemonic) {
        const wallet = await new WalletProvider({ addressPrefix })
            .fromMnemonic({ mnemonic: params.mnemonic, derivationPath: params.derivationPath });
        ensureWalletIntegrity(wallet, params.publicKey);
        return wallet;
    }

    if (params.secretKey) {
        const wallet = await new WalletProvider({ addressPrefix })
            .fromSecretKey(params.secretKey)
        ensureWalletIntegrity(wallet, params.publicKey);
        return wallet;
    }

    throw new Error('Decrypted data does not contain valid keys');
}

const validate = (filePath: string, password: Buffer | Uint8Array) => {
    if (!filePath) {
        throw new Error('File path is required');
    }

    // An empty password is allowed (password length = 0)
    if (!b4a.isBuffer(password)) {
        throw new Error('Password must be a buffer');
    }
}

const decryptKeystore = (fileData: string, password: Buffer | Uint8Array) => {
    const parsed = JSON.parse(fileData)
    if (!parsed.salt || !parsed.nonce || !parsed.ciphertext) {
        throw new Error('Could not decrypt keyfile. Data is invalid or corrupted');
    }

    const encrypted = {
        salt: b4a.from(parsed.salt, 'hex'),
        nonce: b4a.from(parsed.nonce, 'hex'),
        ciphertext: b4a.from(parsed.ciphertext, 'hex')
    }

    // Convert obtained data to a keypair object
    const decryptedBuf = tracCryptoApi.data.decrypt(encrypted, password);
    const walletData = JSON.parse(decryptedBuf.toString('utf8'));

    // Cleanup sensitive data from memory
    tracCryptoApi.utils.memzero(encrypted.salt);
    tracCryptoApi.utils.memzero(encrypted.nonce);
    tracCryptoApi.utils.memzero(encrypted.ciphertext);

    return walletData
}

/**
 * Exports the key pair to an encrypted JSON file.
 * @param {IWallet} wallet - The wallet to be exported
 * @param {string} filePath - Path to save the file.
 * @param {Buffer | Uint8Array} [password] - Buffer used for encryption.
 * @returns {Promise<void>}
 * @throws {Error} If required parameters are missing or invalid, IO-like errors are also propagated.
 */
export const exportWallet = (wallet: IWallet, filePath: string, password: Buffer | Uint8Array = b4a.alloc(0)) => {
    validate(filePath, password)

    if (fs.existsSync(filePath)) {
        throw new Error(`File ${filePath} already exists`);
    }

    const msgBuf = b4a.from(wallet.asJson(), 'utf8');
    const encrypted = tracCryptoApi.data.encrypt(msgBuf, password)

    const fileData = JSON.stringify({
        nonce: b4a.toString(encrypted.nonce, 'hex'),
        salt: b4a.toString(encrypted.salt, 'hex'),
        ciphertext: b4a.toString(encrypted.ciphertext, 'hex')
    });

    try {
        fs.writeFileSync(filePath, fileData);
    } finally {
        // Cleanup sensitive data from memory
        tracCryptoApi.utils.memzero(encrypted.nonce);
        tracCryptoApi.utils.memzero(encrypted.salt);
        tracCryptoApi.utils.memzero(encrypted.ciphertext);
    }
}

/**
 * Imports a key pair from an encrypted JSON file.
 * @param {string} filePath - Path to the file.
 * @param {Buffer | Uint8Array} [password] - Buffer used for decryption.
 * @param {string} [hrp] - Optional address HRP to use when the decrypted payload does not contain one.
 * @returns {Promise<IWallet | IHDWallet>} The imported wallet.
 * @throws {Error} If required parameters are missing or invalid.
 */
export const importFromFile = async (
    filePath: string,
    password: Buffer | Uint8Array = b4a.alloc(0),
    hrp?: string
): Promise<IWallet | IHDWallet> => {
    validate(filePath, password)

    if (!fs.existsSync(filePath)) {
        throw new Error(`File ${filePath} not found`);
    }

    const fileData = fs.readFileSync(filePath, 'utf8')
    const decrypted = decryptKeystore(fileData, password);

    return toWallet(decrypted, hrp);
}
