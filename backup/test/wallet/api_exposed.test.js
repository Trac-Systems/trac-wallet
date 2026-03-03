// wallet API exposed tests
// These tests ensure that the wallet API functions are correctly exposed and callable.
// Testing the functionality of the wallet API itself is done in separate unit tests.

import test from 'brittle';
import PeerWallet from '../../index.js';
import b4a from 'b4a';
import { mnemonic1, networkPrefix } from '../fixtures/fixtures.js';

const mnemonic = mnemonic1;

test('PeerWallet: API methods are exposed', t => {
    t.ok(typeof PeerWallet.decodeBech32m === 'function', 'decodeBech32m method is exposed');
    t.ok(typeof PeerWallet.decodeBech32mSafe === 'function', 'decodeBech32mSafe method is exposed');
    t.ok(typeof PeerWallet.encodeBech32m === 'function', 'encodeBech32m method is exposed');
    t.ok(typeof PeerWallet.encodeBech32mSafe === 'function', 'encodeBech32mSafe method is exposed');
    t.ok(typeof PeerWallet.generateNonce === 'function', 'generateNonce method is exposed');
    t.ok(typeof PeerWallet.blake3 === 'function', 'blake3 method is exposed');
    t.ok(typeof PeerWallet.blake3Safe === 'function', 'blake3Safe method is exposed');
});

test('PeerWallet: generateNonce produces unique nonces', t => {
    const nonce1 = PeerWallet.generateNonce();
    const nonce2 = PeerWallet.generateNonce();

    t.not(b4a.equals(nonce1, nonce2), true, 'Generated nonces are unique');
});

test('PeerWallet: blake3 hashing', async t => {
    const originalData = b4a.from('Blake3');
    const expectedHash = b4a.from('2c4c1fa09b1a3459bc56ac6af6b446c89c784cf9399825f2bede910bed452abe', 'hex');
    const hash = await PeerWallet.blake3(originalData);

    t.ok(b4a.equals(expectedHash, hash), 'Blake3 hashing works correctly');
});

test('PeerWallet: bech32m encoding and decoding works', async t => {
    const wallet = new PeerWallet({ mnemonic, networkPrefix });
    await wallet.ready;

    const address = PeerWallet.encodeBech32m(networkPrefix, wallet.publicKey);
    const decoded = PeerWallet.decodeBech32m(address);

    t.is(wallet.address, address, 'Bech32m encoding and decoding works correctly');
    t.is(b4a.equals(wallet.publicKey, decoded), true, 'Bech32m encoding and decoding works correctly');
});

test('PeerWallet: decodeBech32mSafe handles invalid input gracefully', t => {
    const invalidAddress = 'invalidaddress';

    try {
        const result = PeerWallet.decodeBech32mSafe(invalidAddress);
        t.ok(result === null, 'decodeBech32mSafe correctly handles invalid address');
    } catch (err) {
        t.fail('Safe function throws error for invalid address');
    }
});

test('PeerWallet: encodeBech32mSafe handles invalid input gracefully', t => {
    const invalidData = b4a.from('invaliddata');

    try {
        PeerWallet.encodeBech32mSafe('trac', invalidData);
        t.pass('encodeBech32mSafe correctly handles invalid data');
    } catch (err) {
        t.fail('encodeBech32mSafe should not throw error for invalid data');
    }
});