import test from 'brittle';
import PeerWallet from '../../index.js';
import b4a from 'b4a';
import tracCryptoApi from 'trac-crypto-api';

const mnemonic1 = tracCryptoApi.mnemonic.generate();
const mnemonic2 = tracCryptoApi.mnemonic.generate();
const nonSanitizedMnemonic = '    ' + mnemonic1.toUpperCase() + '    ';
const networkPrefix = 'test';

// TODO: Implement tests covering wrong mnemonic word count (enforce 24). 
// Currently trac-crypto-api is not able to enforce this.
// When this is fixed, implement tests here

const decode = tracCryptoApi.address.decode;
const isValid = (address, prefix, pubKey) => {
    const isString = typeof address === 'string';
    const isNotEmpty = address.length > 0;
    const isValidPrefix = address.startsWith(prefix);
    const isValidPubKey = b4a.equals(decode(address), pubKey);
    return isString && isNotEmpty && isValidPrefix && isValidPubKey;
}

test('PeerWallet: address is a valid string and not empty for all cases', async t => {
    const walletAllOpts = new PeerWallet({ mnemonic: mnemonic1, networkPrefix }); // all options set
    const walletNoPrefix = new PeerWallet({ mnemonic: mnemonic2 }); // no prefix
    const walletNoMnemonic = new PeerWallet({ networkPrefix: 'trac' }); // no mnemonic
    const walletNoOpts = new PeerWallet({}); // no mnemonic and no prefix

    await walletAllOpts.ready;
    await walletNoPrefix.ready;
    await walletNoMnemonic.ready;
    await walletNoOpts.ready;

    // When no mnemonic is provided, address is null until generateKeyPair is invoked
    t.is(walletNoMnemonic.address, null);
    t.is(walletNoMnemonic.publicKey, null);

    t.is(walletNoOpts.address, null);
    t.is(walletNoOpts.publicKey, null);

    await walletNoMnemonic.generateKeyPair();
    await walletNoOpts.generateKeyPair();

    // All options can generate an address
    t.ok(isValid(walletAllOpts.address, networkPrefix, walletAllOpts.publicKey));
    t.ok(isValid(walletNoPrefix.address, 'trac', walletNoPrefix.publicKey));
    t.ok(isValid(walletNoMnemonic.address, 'trac', walletNoMnemonic.publicKey));
    t.ok(isValid(walletNoOpts.address, 'trac', walletNoOpts.publicKey));
});

test('PeerWallet: address is deterministic for same mnemonic and prefix', async t => {
    const wallet1 = new PeerWallet({ mnemonic: mnemonic1, networkPrefix });
    const wallet2 = new PeerWallet({ mnemonic: mnemonic1, networkPrefix });
    await wallet1.ready;
    await wallet2.ready;
    t.is(wallet1.address, wallet2.address);
});

test('PeerWallet: address changes with different mnemonic', async t => {
    const wallet1 = new PeerWallet({ mnemonic: mnemonic1, networkPrefix });
    const wallet2 = new PeerWallet({ mnemonic: mnemonic2, networkPrefix });
    await wallet1.ready;
    await wallet2.ready;
    t.not(wallet1.address, wallet2.address);
});

test('PeerWallet: generates same addresses with sanitized or unsanitized mnemonic input', async t => {
    const wallet1 = new PeerWallet({ mnemonic: nonSanitizedMnemonic, networkPrefix });
    const wallet2 = new PeerWallet({ mnemonic: mnemonic1, networkPrefix });

    await wallet1.ready;
    await wallet2.ready;

    t.ok(isValid(wallet1.address, networkPrefix, wallet1.publicKey));
    t.is(wallet1.address, wallet2.address);
});

test('PeerWallet: address changes with different network prefix', async t => {
    const wallet1 = new PeerWallet({ mnemonic: mnemonic1, networkPrefix: 'trac' });
    const wallet2 = new PeerWallet({ mnemonic: mnemonic1, networkPrefix: 'test' });
    await wallet1.ready;
    await wallet2.ready;
    t.not(wallet1.address, wallet2.address);
    t.ok(wallet1.address.startsWith('trac'));
    t.ok(wallet2.address.startsWith('test'));
});

test('PeerWallet: address is Bech32m encoded', async t => {
    const wallet = new PeerWallet({ mnemonic: mnemonic1, networkPrefix });
    await wallet.ready;
    t.ok(wallet.address.startsWith(networkPrefix));
    t.ok(wallet.address.length > networkPrefix.length);
});

test('PeerWallet: address matches encoding of public key', async t => {
    const wallet = new PeerWallet({ mnemonic: mnemonic1, networkPrefix });
    await wallet.ready;
    const encoded = tracCryptoApi.address.encode(networkPrefix, wallet.publicKey);
    t.is(wallet.address, encoded);
});

test('PeerWallet: address is unique for different public keys', async t => {
    const wallet1 = new PeerWallet({ mnemonic: mnemonic1, networkPrefix });
    const wallet2 = new PeerWallet({ mnemonic: mnemonic2, networkPrefix });
    await wallet1.ready;
    await wallet2.ready;
    t.not(wallet1.publicKey.toString('hex'), wallet2.publicKey.toString('hex'));
    t.not(wallet1.address, wallet2.address);
});