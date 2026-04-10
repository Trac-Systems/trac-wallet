import { test } from 'brittle';
import { WalletProvider } from '../../src/index.ts';
import type { IHDWallet } from '../../src/index.ts';
import { addressPrefix, defaultDerivationPath, nonDefaultDerivationPath } from '../fixtures/fixtures.ts';

const provider = () => new WalletProvider({ addressPrefix })
const seed = '0123456789abcdef'

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

test('WalletProvider#generate: reusing the same seed yields the same mnemonic and address', async t => {
    const wallet1 = await provider().generate({ seed }) as IHDWallet;
    const wallet2 = await provider().generate({ seed }) as IHDWallet;

    t.is(wallet1.mnemonic, wallet2.mnemonic);
    t.is(wallet1.derivationPath, defaultDerivationPath);
    t.is(wallet2.derivationPath, defaultDerivationPath);
    t.is(wallet1.address, wallet2.address);
});

test('WalletProvider#generate: the same seed with another derivation path keeps the mnemonic but changes the address', async t => {
    const wallet1 = await provider().generate({ seed }) as IHDWallet;
    const wallet2 = await provider().generate({
        seed,
        derivationPath: nonDefaultDerivationPath
    }) as IHDWallet;

    t.is(wallet1.mnemonic, wallet2.mnemonic);
    t.is(wallet2.derivationPath, nonDefaultDerivationPath);
    t.not(wallet1.address, wallet2.address);
});
