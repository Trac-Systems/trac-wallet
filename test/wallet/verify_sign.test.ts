import { default as test } from 'brittle';
import { WalletProvider } from '../../src/index.ts';
import tracCryptoApi from 'trac-crypto-api';
import sodium from 'sodium-universal';
import b4a from 'b4a'
import { mnemonic1, mnemonic2, derivationPath, networkPrefix } from '../fixtures/fixtures.js';

const message = b4a.from('hello world');

const randomBytes = (length: number) => {
    const rand = b4a.alloc(length);
    sodium.randombytes_buf(rand);
    return rand;
}

const provider = () => new WalletProvider({ networkPrefix })

test('PeerWallet: sign produces a valid signature', async (t: any) => {
    const wallet = await provider().fromMnemonic({ mnemonic: mnemonic1, derivationPath });
    const signature = wallet.sign(message);
    const verify = wallet.verify(signature, message);
    t.ok(b4a.isBuffer(signature), 'signature is a buffer');
    t.is(signature.length, tracCryptoApi.signature.SIZE, 'signature has correct length');
    t.ok(verify, 'signature is valid');
});

test('PeerWallet: can sign and verify', async (t: any) => {
    const wallet = await provider().fromMnemonic({ mnemonic: mnemonic1, derivationPath });
    const signature = wallet.sign(message);
    const verify = wallet.verify(signature, message);
    t.ok(verify, 'signature is valid');
});

test('PeerWallet: verify returns false for tampered message', async (t: any) => {
    const wallet = await provider().fromMnemonic({ mnemonic: mnemonic1, derivationPath });
    const signature = wallet.sign(message);
    const tampered = b4a.from('hello world!');
    t.not(wallet.verify(signature, tampered), true);
});

test('PeerWallet: verify returns false for tampered signature', async (t: any) => {
    const wallet = await provider().fromMnemonic({ mnemonic: mnemonic1, derivationPath });
    const signature = wallet.sign(message);
    const tamperedSig = randomBytes(signature.length);
    t.not(wallet.verify(tamperedSig, message), true);
});

test('PeerWallet: verify returns false for wrong wallet', async (t: any) => {
    const wallet1 = await provider().fromMnemonic({ mnemonic: mnemonic1, derivationPath });
    const wallet2 = await provider().fromMnemonic({ mnemonic: mnemonic2, derivationPath });
    const signature = wallet1.sign(message);
    t.not(wallet2.verify(signature, message), true);
});
