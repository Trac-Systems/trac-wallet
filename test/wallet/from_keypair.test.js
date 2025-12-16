import test from 'brittle';
import PeerWallet from '../../index.js';
import b4a from 'b4a';
import tracCryptoApi from 'trac-crypto-api';
import { networkPrefix, derivationPath } from '../fixtures/fixtures.js';


async function randomKeyPair() {
    const mnemonic = tracCryptoApi.mnemonic.generate();
    const kp = await tracCryptoApi.address.generate(networkPrefix, mnemonic, derivationPath);
    return { publicKey: kp.publicKey, secretKey: kp.secretKey, address: kp.address };
}

test('Wallet.fromKeyPair: creates wallet from valid keypair', async t => {
    const { publicKey, secretKey, address } = await randomKeyPair();
    const wallet = await PeerWallet.fromKeyPair({ publicKey, secretKey }, networkPrefix);
    await wallet.ready;
    t.ok(b4a.equals(wallet.publicKey, publicKey), 'publicKey matches');
    t.ok(b4a.equals(wallet.secretKey, secretKey), 'secretKey matches');
    t.is(wallet.address, address, 'address matches');
    t.is(wallet.derivationPath, null, 'derivationPath is null');
    t.is(wallet.mnemonic, null, 'mnemonic is null');
});

test('Wallet.fromKeyPair: throws on invalid publicKey', async t => {
    const secretKey = b4a.alloc(tracCryptoApi.address.PRIV_KEY_SIZE);
    const publicKey = b4a.alloc(10); // invalid size
    try {
        await PeerWallet.fromKeyPair({ publicKey, secretKey }, networkPrefix);
        t.fail('Expected error not thrown');
    }
    catch {
        t.pass('throws on invalid publicKey');
    }
});

test('Wallet.fromKeyPair: throws on invalid secretKey', async t => {
    const publicKey = b4a.alloc(tracCryptoApi.address.PUB_KEY_SIZE);
    const secretKey = b4a.alloc(10); // invalid size
    try {
        await PeerWallet.fromKeyPair({ publicKey, secretKey }, networkPrefix);
        t.fail('Expected error not thrown');
    }
    catch {
        t.pass('throws on invalid secretKey');
    }
});
