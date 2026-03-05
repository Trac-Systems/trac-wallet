import test from 'brittle';
import { IHDWallet, WalletProvider } from '../../src/index.ts';
import b4a from 'b4a';
import { join } from 'path';
import fs from 'fs';
import { mnemonic1, networkPrefix } from '../fixtures/fixtures.js';
import { exportWallet, importFromFile } from '../../src/exporter.ts';

const mnemonic = mnemonic1;
const password = b4a.from('testpassword');
const filePath = join('./test-keyfile.json');

test('PeerWallet: export and import preserves keypair', async t => {
    const derivationPath = "m/44'/0'/0'/0'/0'";
    const wallet = await new WalletProvider({ networkPrefix }).fromMnemonic({ mnemonic, derivationPath });
    exportWallet(wallet, filePath, password);

    const importedWallet = await importFromFile(filePath, password) as IHDWallet;

    t.ok(b4a.equals(wallet.publicKey, importedWallet.publicKey));
    t.ok(b4a.equals(wallet.secretKey, importedWallet.secretKey));
    t.is(wallet.address, importedWallet.address);
    t.is(wallet.derivationPath, derivationPath);
    t.is(wallet.derivationPath, importedWallet.derivationPath);
    fs.unlinkSync(filePath);
});

test('PeerWallet: password can be empty', async t => {
    const derivationPath = "m/44'/0'/0'/0'/0'";
    const wallet = await new WalletProvider({ networkPrefix }).fromMnemonic({ mnemonic, derivationPath });
    const emptyPassword = b4a.alloc(0);
    exportWallet(wallet, filePath, emptyPassword);

    const importedWallet = await importFromFile(filePath, emptyPassword) as IHDWallet;

    t.ok(b4a.equals(wallet.publicKey, importedWallet.publicKey));
    t.ok(b4a.equals(wallet.secretKey, importedWallet.secretKey));
    t.is(wallet.mnemonic, importedWallet.mnemonic);
    t.is(wallet.address, importedWallet.address);
    t.is(wallet.derivationPath, derivationPath);
    t.is(wallet.derivationPath, importedWallet.derivationPath);
    fs.unlinkSync(filePath);
});

test('PeerWallet: import throws if file does not exist', async t => {
    const filename = 'nonexistent.json';
    try {
        importFromFile(filename, password);
        t.fail('Expected error not thrown');
    } catch (error: any) {
        t.is(error.message, `Error reading file: File ${filename} not found`);
    }
});

test('PeerWallet: import throws if password is wrong', async t => {
    const derivationPath = "m/44'/0'/0'/0'/0'";
    const wallet = await new WalletProvider({ networkPrefix }).fromMnemonic({ mnemonic, derivationPath });
    exportWallet(wallet, filePath, password);

    const wrongPassword = b4a.from('wrongpassword');
    try {
        importFromFile(filePath, wrongPassword);
        t.fail('Expected error not thrown');
    } catch (error: any) {
        t.is(error.message, 'Failed to decrypt data. Invalid key or corrupted data.');
    }
    fs.unlinkSync(filePath);
});

test('PeerWallet: export throws if password is not a buffer', async t => {
    const wallet = await new WalletProvider({ networkPrefix }).fromMnemonic({ mnemonic });
    try {
        exportWallet(wallet, filePath, 'notabuffer' as any as Buffer); // I guess this is useful to test runtime logic
        t.fail('Expected error not thrown');
    } catch (error: any) {
        t.is(error.message, 'Password must be a buffer');
    }
});

test('PeerWallet: import throws if password is not a buffer', async t => {
    const derivationPath = "m/44'/0'/0'/0'/0'";
    const wallet = await new WalletProvider({ networkPrefix }).fromMnemonic({ mnemonic, derivationPath });
    exportWallet(wallet, filePath, password);
    try {
        importFromFile(filePath, 'notabuffer' as any as Buffer);
        t.fail('Expected error not thrown');
    } catch (error: any) {
        t.is(error.message, 'Password must be a buffer');
    }
    fs.unlinkSync(filePath);
});
