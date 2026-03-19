import test from 'brittle';
import { IHDWallet, WalletProvider } from '../../src/index.ts';
import b4a from 'b4a';
import { join } from 'path';
import fs from 'fs';
import tracCryptoApi from 'trac-crypto-api';
import { mnemonic1, addressPrefix, secretKey } from '../fixtures/fixtures.ts';
import { exportWallet, importFromFile } from '../../src/exporter.ts';

const mnemonic = mnemonic1;
const password = b4a.from('testpassword');
const createFilePath = () => join('.', `test-keyfile-${Date.now()}-${Math.random().toString(16).slice(2)}.json`);
const cleanup = (filePath: string) => fs.existsSync(filePath) && fs.unlinkSync(filePath)

const writeEncryptedKeystore = (
    filePath: string,
    payload: Record<string, unknown>,
    key: Buffer | Uint8Array = password
) => {
    const msgBuf = b4a.from(JSON.stringify(payload), 'utf8');
    const encrypted = tracCryptoApi.data.encrypt(msgBuf, key);

    const fileData = JSON.stringify({
        nonce: b4a.toString(encrypted.nonce, 'hex'),
        salt: b4a.toString(encrypted.salt, 'hex'),
        ciphertext: b4a.toString(encrypted.ciphertext, 'hex')
    });

    fs.writeFileSync(filePath, fileData);
}

test('exporter: export and import preserves keypair', async t => {
    const filePath = createFilePath();
    t.teardown(() => cleanup(filePath));

    const derivationPath = "m/44'/0'/0'/0'/0'";
    const wallet = await new WalletProvider({ addressPrefix }).fromMnemonic({ mnemonic, derivationPath });
    exportWallet(wallet, filePath, password);

    const importedWallet = await importFromFile(filePath, password) as IHDWallet;

    t.ok(b4a.equals(wallet.publicKey, importedWallet.publicKey));
    t.ok(b4a.equals(wallet.secretKey, importedWallet.secretKey));
    t.is(wallet.address, importedWallet.address);
    t.is(wallet.derivationPath, derivationPath);
    t.is(wallet.derivationPath, importedWallet.derivationPath);
});

test('exporter: password can be empty', async t => {
    const filePath = createFilePath();
    t.teardown(() => cleanup(filePath));

    const derivationPath = "m/44'/0'/0'/0'/0'";
    const wallet = await new WalletProvider({ addressPrefix }).fromMnemonic({ mnemonic, derivationPath });
    const emptyPassword = b4a.alloc(0);
    exportWallet(wallet, filePath, emptyPassword);

    const importedWallet = await importFromFile(filePath, emptyPassword) as IHDWallet;

    t.ok(b4a.equals(wallet.publicKey, importedWallet.publicKey));
    t.ok(b4a.equals(wallet.secretKey, importedWallet.secretKey));
    t.is(wallet.mnemonic, importedWallet.mnemonic);
    t.is(wallet.address, importedWallet.address);
    t.is(wallet.derivationPath, derivationPath);
    t.is(wallet.derivationPath, importedWallet.derivationPath);
});

test('exporter: import throws if file does not exist', async t => {
    const filename = 'nonexistent.json';
    try {
        await importFromFile(filename, password);
        t.fail('Expected error not thrown');
    } catch (error: any) {
        t.is(error.message, `File ${filename} not found`);
    }
});

test('exporter: validate throws if file path is empty', async t => {
    try {
        await importFromFile('', password);
        t.fail('Expected error not thrown');
    } catch (error: any) {
        t.is(error.message, 'File path is required');
    }
});

test('exporter: import throws if keystore payload is invalid or corrupted', async t => {
    const filePath = createFilePath();
    t.teardown(() => cleanup(filePath));

    fs.writeFileSync(filePath, JSON.stringify({ nonce: 'invalid', ciphertext: 'data' }));
    try {
        await importFromFile(filePath, password);
        t.fail('Expected error not thrown');
    } catch (error: any) {
        t.is(error.message, 'Could not decrypt keyfile. Data is invalid or corrupted');
    }
});

test('exporter: import uses provided hrp when decrypted payload misses addressPrefix', async t => {
    const filePath = createFilePath();
    t.teardown(() => cleanup(filePath));

    const derivationPath = "m/44'/0'/0'/0'/0'";
    const expectedWallet = await new WalletProvider({ addressPrefix }).fromMnemonic({ mnemonic, derivationPath });

    writeEncryptedKeystore(filePath, {
        mnemonic,
        derivationPath
    });

    const importedWallet = await importFromFile(filePath, password, addressPrefix) as IHDWallet;

    t.is(importedWallet.address, expectedWallet.address);
    t.is(importedWallet.derivationPath, derivationPath);
});

test('exporter: import throws if decrypted payload misses addressPrefix and hrp', async t => {
    const filePath = createFilePath();
    t.teardown(() => cleanup(filePath));

    writeEncryptedKeystore(filePath, {
        mnemonic,
        derivationPath: "m/44'/0'/0'/0'/0'"
    });

    try {
        await importFromFile(filePath, password);
        t.fail('Expected error not thrown');
    } catch (error: any) {
        t.is(error.message, 'Imported keystore is incompatible with this wallet version');
    }
});

test('exporter: import throws if keystore version is unsupported', async t => {
    const filePath = createFilePath();
    t.teardown(() => cleanup(filePath));

    writeEncryptedKeystore(filePath, {
        addressPrefix,
        mnemonic,
        derivationPath: "m/44'/0'/0'/0'/0'",
        version: '1.2.0'
    });

    try {
        await importFromFile(filePath, password);
        t.fail('Expected error not thrown');
    } catch (error: any) {
        t.is(error.message, 'Imported keystore version is not supported');
    }
});

test('exporter: import can build wallet from secretKey payload', async t => {
    const filePath = createFilePath();
    t.teardown(() => cleanup(filePath));

    const secretKeyHex = b4a.toString(secretKey, 'hex');
    const expectedWallet = await new WalletProvider({ addressPrefix }).fromSecretKey(secretKeyHex);

    writeEncryptedKeystore(filePath, {
        addressPrefix,
        secretKey: secretKeyHex
    });

    const importedWallet = await importFromFile(filePath, password);
    t.ok(b4a.equals(expectedWallet.publicKey, importedWallet.publicKey));
    t.ok(b4a.equals(expectedWallet.secretKey, importedWallet.secretKey));
    t.is(expectedWallet.address, importedWallet.address);
});

test('exporter: import throws if baked publicKey does not match derived wallet', async t => {
    const filePath = createFilePath();
    t.teardown(() => cleanup(filePath));

    writeEncryptedKeystore(filePath, {
        addressPrefix,
        mnemonic,
        derivationPath: "m/44'/0'/0'/0'/0'",
        publicKey: '00'.repeat(tracCryptoApi.address.PUB_KEY_SIZE)
    });

    try {
        await importFromFile(filePath, password);
        t.fail('Expected error not thrown');
    } catch (error: any) {
        t.is(error.message, 'Imported keystore publicKey does not match the derived wallet');
    }
});

test('exporter: import throws when decrypted payload has no keys', async t => {
    const filePath = createFilePath();
    t.teardown(() => cleanup(filePath));

    writeEncryptedKeystore(filePath, { addressPrefix });

    try {
        await importFromFile(filePath, password);
        t.fail('Expected error not thrown');
    } catch (error: any) {
        t.is(error.message, 'Decrypted data does not contain valid keys');
    }
});

test('exporter: export throws if file already exists', async t => {
    const filePath = createFilePath();
    t.teardown(() => cleanup(filePath));

    const wallet = await new WalletProvider({ addressPrefix }).fromMnemonic({ mnemonic });
    exportWallet(wallet, filePath, password); // creates the file so when we attempt, it already exists.

    try {
        exportWallet(wallet, filePath, password);
        t.fail('Expected error not thrown');
    } catch (error: any) {
        t.is(error.message, `File ${filePath} already exists`);
    }
});

test('exporter: import throws if password is wrong', async t => {
    const filePath = createFilePath();
    t.teardown(() => cleanup(filePath));

    const derivationPath = "m/44'/0'/0'/0'/0'";
    const wallet = await new WalletProvider({ addressPrefix }).fromMnemonic({ mnemonic, derivationPath });
    exportWallet(wallet, filePath, password);

    const wrongPassword = b4a.from('wrongpassword');
    try {
        await importFromFile(filePath, wrongPassword);
        t.fail('Expected error not thrown');
    } catch (error: any) {
        t.is(error.message, 'Failed to decrypt data. Invalid key or corrupted data.');
    }
});

test('exporter: export throws if password is not a buffer', async t => {
    const filePath = createFilePath();

    const wallet = await new WalletProvider({ addressPrefix }).fromMnemonic({ mnemonic });
    try {
        exportWallet(wallet, filePath, 'notabuffer' as any as Buffer); // I guess this is useful to test runtime logic
        t.fail('Expected error not thrown');
    } catch (error: any) {
        t.is(error.message, 'Password must be a buffer');
    }
});

test('exporter: import throws if password is not a buffer', async t => {
    const filePath = createFilePath();
    t.teardown(() => cleanup(filePath));

    const derivationPath = "m/44'/0'/0'/0'/0'";
    const wallet = await new WalletProvider({ addressPrefix }).fromMnemonic({ mnemonic, derivationPath });
    exportWallet(wallet, filePath, password);
    try {
        await importFromFile(filePath, 'notabuffer' as any as Buffer);
        t.fail('Expected error not thrown');
    } catch (error: any) {
        t.is(error.message, 'Password must be a buffer');
    }
});
