import test from 'brittle';
import PeerWallet from '../../index.js';
import b4a from 'b4a';
import tracCryptoApi from 'trac-crypto-api';

function isNode() {
    return typeof process !== 'undefined' &&
    process.versions != null &&
    process.versions.node != null;
}

let slip10 = null;

// This test only works on Node.js because slip10 relies on native modules not available in Bare.
// For this reason, this was deactivated on anything that is not a Node environment
test('PeerWallet: should create a valid HD wallet from micro-key-producer based on peer wallet mnemonic, then HD wallet signs a message and is verified by both HD and PeerWallet.', async t => {
    if (isNode()) {
        slip10 = await import('micro-key-producer/slip10.js');
    }
    else {
        t.comment('Skipping HD wallet test in non-Node environment');
        return;
    }
    const mnemonic = tracCryptoApi.mnemonic.generate();
    const walletLocal = new PeerWallet();
    await walletLocal.ready;
    await walletLocal.generateKeyPair(mnemonic);
    const seed = await tracCryptoApi.mnemonic.toSeed(mnemonic);
    const seed32 = tracCryptoApi.hash.sha256(seed);

    const msg = 'this is a test';
    const msgHex = b4a.toString(b4a.from(msg, 'utf8'), 'hex');

    const hdkey = slip10.HDKey.fromMasterSeed(seed32);
    const sig = hdkey.sign(msgHex);

    const hd_verify = hdkey.verify(msgHex, sig);
    const native_verify = walletLocal.verify(b4a.from(sig), b4a.from(msgHex, 'hex'), b4a.from(hdkey.publicKeyRaw));

    // reverse case tested through micro-key-producer hacking because it doesn't support off-wallet verify.
    // confirmed to work.
    /*
    const sig2 = walletLocal.sign(msg);
    const hd_verify2 = hdkey.verify2(b4a.toString(b4a.from(msg, 'utf8'), 'hex'), sig2, walletLocal.publicKey);
    console.log(hd_verify2)*/

    t.is(hd_verify, native_verify);
});