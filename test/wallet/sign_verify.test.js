import test from 'brittle';
import PeerWallet from '../../index.js';
import b4a from 'b4a';
import tracCryptoApi from 'trac-crypto-api';
import sodium from 'sodium-universal';

const mnemonic1 = tracCryptoApi.mnemonic.generate();
const mnemonic2 = tracCryptoApi.mnemonic.generate();
const message = b4a.from('hello world');

function randomBytes(length) {
    const rand = b4a.alloc(length);
    sodium.randombytes_buf(rand);
    return rand;
}

test('PeerWallet: sign produces a valid signature', async t => {
    const wallet = new PeerWallet({ mnemonic: mnemonic1 });
    await wallet.ready;
    const signature = wallet.sign(message);
    const verify = wallet.verify(signature, message, wallet.publicKey);
    t.ok(b4a.isBuffer(signature), 'signature is a buffer');
    t.is(signature.length, tracCryptoApi.signature.SIZE, 'signature has correct length');
    t.ok(verify, 'signature is valid');
});

test('PeerWallet: can verify signature from another wallet', async t => {
    const wallet1 = new PeerWallet({ mnemonic: mnemonic1 });
    const wallet2 = new PeerWallet({ mnemonic: mnemonic2 });
    await wallet1.ready;
    await wallet2.ready;
    const signature = wallet1.sign(message);
    const verify = wallet2.verify(signature, message, wallet1.publicKey);
    t.ok(verify, 'signature is valid');
});

test('PeerWallet: verify returns false for tampered message', async t => {
    const wallet = new PeerWallet({ mnemonic: mnemonic1 });
    await wallet.ready;
    const signature = wallet.sign(message);
    const tampered = b4a.from('hello world!');
    t.not(wallet.verify(signature, tampered, wallet.publicKey), true);
});

test('PeerWallet: verify returns false for tampered signature', async t => {
    const wallet = new PeerWallet({ mnemonic: mnemonic1 });
    await wallet.ready;
    const signature = wallet.sign(message);
    const tamperedSig = randomBytes(signature.length);
    t.not(wallet.verify(tamperedSig, message, wallet.publicKey), true);
});

test('PeerWallet: verify returns false for wrong public key', async t => {
    const wallet1 = new PeerWallet({ mnemonic: mnemonic1 });
    const wallet2 = new PeerWallet({ mnemonic: mnemonic2 });
    await wallet1.ready;
    await wallet2.ready;
    const signature = wallet1.sign(message);
    t.not(wallet2.verify(signature, message, wallet2.publicKey), true);
});

test('PeerWallet: sign returns empty buffer if no secret key', async t => {
    const wallet = new PeerWallet({});
    await wallet.ready;
    const signature = wallet.sign(message);
    t.is(signature.length, 0);
});
