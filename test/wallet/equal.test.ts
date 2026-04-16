import { test } from 'brittle';
import { WalletProvider } from '../../src/index.ts';
// @ts-ignore (should be removed after the js-docs are corrected on trac-crypto-api)
import tracCryptoApi from 'trac-crypto-api';
import b4a from 'b4a'
import { mnemonic1, nonDefaultDerivationPath, addressPrefix, mnemonic2, secretKey } from '../fixtures/fixtures.ts';

const message = b4a.from('hello world');
const provider = () => new WalletProvider({ addressPrefix })
const anotherNetworkProvider = () => new WalletProvider({ addressPrefix: 'testtrac' })

test('Wallet: verication of signatures means equality', async t => {
    // @ts-ignore (should be removed after the js-docs are corrected on trac-crypto-api)
    const { secretKey } = await tracCryptoApi.address.generate(addressPrefix, mnemonic1, nonDefaultDerivationPath);
    const wallet1 = await provider().fromMnemonic({ mnemonic: mnemonic1, derivationPath: nonDefaultDerivationPath });
    const wallet2 = await provider().fromSecretKey(b4a.toString(secretKey, 'hex'));

    const signature = wallet1.sign(message);
    const verify = wallet2.verify(signature, message);
    t.ok(verify, 'verification works');
    t.ok(wallet1.equals(wallet2));
});

test('Wallet: same type doesnt mean equality', async t => {
    const wallet1 = await provider().fromMnemonic({ mnemonic: mnemonic1 });
    const wallet2 = await provider().fromMnemonic({ mnemonic: mnemonic2 });

    t.ok(!wallet1.equals(wallet2));
});

test('Wallet: prefix doesnt play a role in the signature, but changes equality', async t => {
    const wallet1 = await provider().fromSecretKey(b4a.toString(secretKey, 'hex'));
    const wallet2 = await anotherNetworkProvider().fromSecretKey(b4a.toString(secretKey, 'hex'));

    const signature = wallet1.sign(message);
    const verify = wallet2.verify(signature, message);
    t.ok(verify, 'verification works');
    t.ok(!wallet1.equals(wallet2));
    t.ok(b4a.equals(wallet1.secretKey, wallet2.secretKey));
});
