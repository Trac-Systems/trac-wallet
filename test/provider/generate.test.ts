import { test } from 'brittle';
import { WalletProvider } from '../../src/index.ts';
import type { IHDWallet } from '../../src/index.ts';
import { addressPrefix, nonDefaultDerivationPath } from '../fixtures/fixtures.ts';

const provider = () => new WalletProvider({ addressPrefix })

test('WalletProvider#generate: creates a wallet', async t => {
    const wallet = await provider().generate() as IHDWallet;
    t.ok(wallet);
    t.not(wallet.mnemonic, undefined);
    t.not(wallet.derivationPath, undefined);
});

test('WalletProvider#generate: reusing mnemonic with the same derivation path yields the same address', async t => {
    const generatedWallet = await provider().generate({ derivationPath: nonDefaultDerivationPath }) as IHDWallet;
    const recreatedWallet = await provider().fromMnemonic({
        mnemonic: generatedWallet.mnemonic,
        derivationPath: nonDefaultDerivationPath
    });

    t.is(generatedWallet.derivationPath, nonDefaultDerivationPath);
    t.is(recreatedWallet.derivationPath, nonDefaultDerivationPath);
    t.is(generatedWallet.address, recreatedWallet.address);
});
