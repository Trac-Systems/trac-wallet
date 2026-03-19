import { test } from 'brittle';
import { WalletProvider } from '../../src/index.ts';
import type { IHDWallet } from '../../src/index.ts';
import { addressPrefix } from '../fixtures/fixtures.ts';

const provider = () => new WalletProvider({ addressPrefix })

test('WalletProvider#generate: creates a wallet', async t => {
    const wallet = await provider().generate() as IHDWallet;
    t.ok(wallet);
    t.not(wallet.mnemonic, undefined);
    t.not(wallet.derivationPath, undefined);
});
