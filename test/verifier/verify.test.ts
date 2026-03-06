import { test } from 'brittle';
import { WalletProvider } from '../../src/index.ts';
import { Verifier } from '../../src/index.ts';
import sodium from 'sodium-universal';
import b4a from 'b4a'
import { mnemonic1, mnemonic2, nonDefaultDerivationPath, networkPrefix } from '../fixtures/fixtures.ts';
import tracCryptoApi from 'trac-crypto-api';

const message = b4a.from('hello world');

const randomBytes = (length: number) => {
    const rand = b4a.alloc(length);
    sodium.randombytes_buf(rand);
    return rand;
}

const provider = () => new WalletProvider({ addressPrefix: networkPrefix })

test('Verifier: constructor throws for invalid public key length', (t: any) => {
    const invalidPublicKey = b4a.alloc(tracCryptoApi.address.PUB_KEY_SIZE - 1);
    try {
        new Verifier(invalidPublicKey);
        t.fail('Expected error not thrown');
    } catch (error: any) {
        t.is(
            error.message,
            `Invalid public key. Expected a Buffer of length ${tracCryptoApi.address.PUB_KEY_SIZE}, got ${tracCryptoApi.address.PUB_KEY_SIZE - 1}`
        );
    }
});

test('Verifier: constructor throws for non-buffer public key', (t: any) => {
    try {
        new Verifier('not-a-buffer' as any);
        t.fail('Expected error not thrown');
    } catch (error: any) {
        t.is(
            error.message,
            `Invalid public key. Expected a Buffer of length ${tracCryptoApi.address.PUB_KEY_SIZE}, got 12`
        );
    }
});

test('Verifier: verify returns true for valid wallet signature', async (t: any) => {
    const wallet = await provider().fromMnemonic({ mnemonic: mnemonic1, derivationPath: nonDefaultDerivationPath });
    const verifier = new Verifier(wallet.publicKey);
    const signature = wallet.sign(message);
    t.ok(b4a.equals(verifier.publicKey, wallet.publicKey), 'public key matches');
    t.ok(verifier.verify(signature, message), 'signature is valid');
});

test('Verifier: can verify wallet signature', async (t: any) => {
    const wallet = await provider().fromMnemonic({ mnemonic: mnemonic1, derivationPath: nonDefaultDerivationPath });
    const verifier = new Verifier(wallet.publicKey);
    const signature = wallet.sign(message);
    const verify = verifier.verify(signature, message);
    t.ok(verify, 'signature is valid');
});

test('Verifier: verify returns false for tampered message', async (t: any) => {
    const wallet = await provider().fromMnemonic({ mnemonic: mnemonic1, derivationPath: nonDefaultDerivationPath });
    const verifier = new Verifier(wallet.publicKey);
    const signature = wallet.sign(message);
    const tampered = b4a.from('hello world!');
    t.not(verifier.verify(signature, tampered), true);
});

test('Verifier: verify returns false for tampered signature', async (t: any) => {
    const wallet = await provider().fromMnemonic({ mnemonic: mnemonic1, derivationPath: nonDefaultDerivationPath });
    const verifier = new Verifier(wallet.publicKey);
    const signature = wallet.sign(message);
    const tamperedSig = randomBytes(signature.length);
    t.not(verifier.verify(tamperedSig, message), true);
});

test('Verifier: verify returns false for wrong public key', async (t: any) => {
    const wallet1 = await provider().fromMnemonic({ mnemonic: mnemonic1, derivationPath: nonDefaultDerivationPath });
    const wallet2 = await provider().fromMnemonic({ mnemonic: mnemonic2, derivationPath: nonDefaultDerivationPath });
    const verifier = new Verifier(wallet2.publicKey);
    const signature = wallet1.sign(message);
    t.not(verifier.verify(signature, message), true);
});
