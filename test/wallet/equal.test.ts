import { test } from 'brittle';
import { WalletProvider } from '../../src/index.ts';
import tracCryptoApi from 'trac-crypto-api';
import b4a from 'b4a'
import { mnemonic1, nonDefaultDerivationPath, networkPrefix, mnemonic2 } from '../fixtures/fixtures.js';

const message = b4a.from('hello world');

const provider = () => new WalletProvider({ networkPrefix })
const anotherNetworkProvider = () => new WalletProvider({ networkPrefix: 'testtrac' })

test('Wallet: verication of signatures means equality', async (t: any) => {
    // @ts-ignore
    const { secretKey } = await tracCryptoApi.address.generate(networkPrefix, mnemonic1, nonDefaultDerivationPath);
    const wallet1 = await provider().fromMnemonic({ mnemonic: mnemonic1, derivationPath: nonDefaultDerivationPath });
    const wallet2 = await provider().fromSecretKey(b4a.toString(secretKey, 'hex'));

    const signature = wallet1.sign(message);
    const verify = wallet2.verify(signature, message);
    t.ok(verify, 'verification works');
    t.ok(wallet1.equals(wallet2));
});

test('Wallet: same type doesnt mean equality', async (t: any) => {
    const wallet1 = await provider().fromMnemonic({ mnemonic: mnemonic1 });
    const wallet2 = await provider().fromMnemonic({ mnemonic: mnemonic2 });

    t.ok(!wallet1.equals(wallet2));
});

test('Wallet: prefix doesnt play a role in the signature (or equality)', async (t: any) => {
    // @ts-ignore
    const { secretKey } = await tracCryptoApi.address.generate(networkPrefix, mnemonic1, nonDefaultDerivationPath);
    const wallet1 = await provider().fromSecretKey(b4a.toString(secretKey, 'hex'));
    const wallet2 = await anotherNetworkProvider().fromSecretKey(b4a.toString(secretKey, 'hex'));

    const signature = wallet1.sign(message);
    const verify = wallet2.verify(signature, message);
    t.ok(verify, 'verification works');
    t.ok(wallet1.equals(wallet2));
    t.ok(wallet1.address !== wallet2.address);
});
