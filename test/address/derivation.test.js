import test from 'brittle';
import PeerWallet from '../../index.js';
import b4a from 'b4a';
import {
    mnemonic1,
    networkPrefix
} from '../fixtures/fixtures.js';

const mnemonic = mnemonic1;
const validPaths = [
    "m/0'", // minimum valid segment
    "m/2147483647'", // maximum valid segment
    "m/44'/0'/0'/0'/0'", // standard BIP44 path
    "m/44'/0'/0'/0'/1'", // slight variation
];

const invalidPaths = [
    {}, // non-string
    "m/0", // non-hardened segment
    "m/2147483648'", // bigger than maximum valid segment
    "invalid/path"
];

test('Derivation: generates different addresses for different paths', async t => {
    const addresses = [];
    for (const path of validPaths) {
        const w = new PeerWallet({ networkPrefix, mnemonic, derivationPath: path });
        await w.ready;
        addresses.push(w.address);
        console.log(`Path: ${path} => Address: ${w.address}`);
        console.log(`Path: ${path} => PATH: ${w.derivationPath}`);
    }

    t.is(new Set(addresses).size, addresses.length, 'All derived addresses are unique');
});

test('Derivation: same path yields same address', async t => {
    const path = validPaths[0];
    const w1 = new PeerWallet({ networkPrefix, mnemonic, derivationPath: path });
    const w2 = new PeerWallet({ networkPrefix, mnemonic, derivationPath: path });
    await w1.ready;
    await w2.ready;
    t.is(w1.address, w2.address);
    t.ok(b4a.equals(w1.publicKey, w2.publicKey));
});

test('Derivation: different paths yield different public keys', async t => {
    const w1 = new PeerWallet({ networkPrefix, mnemonic, derivationPath: validPaths[0] });
    const w2 = new PeerWallet({ networkPrefix, mnemonic, derivationPath: validPaths[1] });
    await w1.ready;
    await w2.ready;
    t.not(w1.address, w2.address);
    t.not(b4a.toString(w1.publicKey, 'hex'), b4a.toString(w2.publicKey, 'hex'));
});

test('Derivation: invalid path throws error', async t => {
    for (const path of invalidPaths) {
        try {
            const w = new PeerWallet({ networkPrefix, mnemonic, derivationPath: path });
            await w.ready;
            t.fail(`Should throw error for invalid path: ${path}`);
        } catch (e) {
            t.pass(`Throws for invalid path: ${path}`);
        }
    }
});