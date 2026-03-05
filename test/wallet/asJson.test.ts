import { test } from 'brittle';
import { WalletProvider } from '../../src/index.ts';
import b4a from 'b4a';
import { mnemonic1, networkPrefix, nonDefaultDerivationPath, secretKey } from '../fixtures/fixtures.ts';

const provider = () => new WalletProvider({ networkPrefix })
const asHex = (value: Buffer | Uint8Array): string => b4a.toString(value, 'hex')

test('Wallet#asJson: serializes and can be parsed with expected properties', async t => {
    const wallet = await provider().fromSecretKey(asHex(secretKey));
    const parsed = JSON.parse(wallet.asJson());

    t.is(parsed.networkPrefix, networkPrefix);
    t.is(parsed.publicKey, asHex(wallet.publicKey));
    t.is(parsed.secretKey, asHex(secretKey));
    t.is(parsed.address, wallet.address);
});

test('Wallet#asJson: fromMnemonic serializes hd fields and can be parsed', async t => {
    const wallet = await provider().fromMnemonic({
        mnemonic: mnemonic1,
        derivationPath: nonDefaultDerivationPath
    });
    const parsed = JSON.parse(wallet.asJson());

    t.is(parsed.networkPrefix, networkPrefix);
    t.is(parsed.publicKey, asHex(wallet.publicKey));
    t.is(parsed.secretKey, asHex(wallet.secretKey));
    t.is(parsed.address, wallet.address);
    t.is(parsed.mnemonic, mnemonic1);
    t.is(parsed.derivationPath, nonDefaultDerivationPath);
});
