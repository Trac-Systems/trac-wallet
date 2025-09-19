import test from 'brittle';
import PeerWallet from '../../index.js';
import b4a from 'b4a';
import { join } from 'path';
import fs from 'fs';
import tracCryptoApi from 'trac-crypto-api';
import {
    mnemonic1,
    networkPrefix
} from '../fixtures/fixtures.js';

const mnemonic = mnemonic1;
const password = b4a.from('testpassword');
const filePath = join('./test-keyfile.json');

test('PeerWallet: export and import preserves keypair', async t => {
    const derivationPath = "m/44'/0'/0'/0'/0'";
    const wallet = new PeerWallet({ mnemonic, derivationPath, networkPrefix });
    await wallet.ready;
    wallet.exportToFile(filePath, password);

    const importedWallet = new PeerWallet({ networkPrefix });
    await importedWallet.ready;
    importedWallet.importFromFile(filePath, password);

    t.ok(b4a.equals(wallet.publicKey, importedWallet.publicKey));
    t.ok(b4a.equals(wallet.secretKey, importedWallet.secretKey));
    t.is(wallet.mnemonic, importedWallet.mnemonic);
    t.is(wallet.address, importedWallet.address);
    t.is(wallet.derivationPath, derivationPath);
    t.is(wallet.derivationPath, importedWallet.derivationPath);
    fs.unlinkSync(filePath);
});

test('PeerWallet: password can be empty', async t => {
    const derivationPath = "m/44'/0'/0'/0'/0'";
    const wallet = new PeerWallet({ mnemonic, derivationPath, networkPrefix });
    await wallet.ready;
    const emptyPassword = b4a.alloc(0);
    wallet.exportToFile(filePath, emptyPassword);

    const importedWallet = new PeerWallet({ networkPrefix });
    await importedWallet.ready;
    importedWallet.importFromFile(filePath, emptyPassword);

    t.ok(b4a.equals(wallet.publicKey, importedWallet.publicKey));
    t.ok(b4a.equals(wallet.secretKey, importedWallet.secretKey));
    t.is(wallet.mnemonic, importedWallet.mnemonic);
    t.is(wallet.address, importedWallet.address);
    t.is(wallet.derivationPath, derivationPath);
    t.is(wallet.derivationPath, importedWallet.derivationPath);
    fs.unlinkSync(filePath);
});

test('PeerWallet: export throws if no secret key', async t => {
    const wallet = new PeerWallet({});
    await wallet.ready;
    try {
        wallet.exportToFile(filePath, password);
        t.fail('Expected error not thrown');
    } catch (error) {
        t.is(error.message, 'No key pair stored');
    }
});

test('PeerWallet: import throws if file does not exist', async t => {
    const filename = 'nonexistent.json';
    const wallet = new PeerWallet();
    await wallet.ready;
    try {
        wallet.importFromFile(filename, password);
        t.fail('Expected error not thrown');
    } catch (error) {
        t.is(error.message, `Error reading file: File ${filename} not found`);
    }
});

test('PeerWallet: import throws if password is wrong', async t => {
    const wallet = new PeerWallet({ mnemonic });
    await wallet.ready;
    wallet.exportToFile(filePath, password);
    const importedWallet = new PeerWallet();
    await importedWallet.ready;
    const wrongPassword = b4a.from('wrongpassword');
    try {
        importedWallet.importFromFile(filePath, wrongPassword);
        t.fail('Expected error not thrown');
    } catch (error) {
        t.is(error.message, 'Failed to decrypt data. Invalid key or corrupted data.');
    }
    fs.unlinkSync(filePath);
});

test('PeerWallet: export throws if password is not a buffer', async t => {
    const wallet = new PeerWallet({ mnemonic });
    await wallet.ready;
    try {
        wallet.exportToFile(filePath, 'notabuffer');
        t.fail('Expected error not thrown');
    } catch (error) {
        t.is(error.message, 'Password must be a buffer');
    }
});

test('PeerWallet: import throws if password is not a buffer', async t => {
    const wallet = new PeerWallet({ mnemonic });
    await wallet.ready;
    wallet.exportToFile(filePath, password);
    const importedWallet = new PeerWallet();
    await importedWallet.ready;
    try {
        importedWallet.importFromFile(filePath, 'notabuffer');
        t.fail('Expected error not thrown');
    } catch (error) {
        t.is(error.message, 'Password must be a buffer');
    }
    fs.unlinkSync(filePath);
});
