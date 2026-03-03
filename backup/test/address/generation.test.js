import test from 'brittle';
import PeerWallet from '../../index.js';
import tracCryptoApi from 'trac-crypto-api';
import {
    mnemonic1,
    mnemonic2,
    nonSanitizedMnemonic,
    networkPrefix,
    isAddressValid
} from '../fixtures/fixtures.js';

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
    t.ok(isAddressValid(walletAllOpts.address, networkPrefix, walletAllOpts.publicKey));
    t.ok(isAddressValid(walletNoPrefix.address, 'trac', walletNoPrefix.publicKey));
    t.ok(isAddressValid(walletNoMnemonic.address, 'trac', walletNoMnemonic.publicKey));
    t.ok(isAddressValid(walletNoOpts.address, 'trac', walletNoOpts.publicKey));
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

    t.ok(isAddressValid(wallet1.address, networkPrefix, wallet1.publicKey));
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