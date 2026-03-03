import { test } from 'brittle';
import { WalletProvider } from '../../src/index.ts';
import { networkPrefix, defaultDerivationPath, nonDefaultDerivationPath } from '../fixtures/fixtures.js';

const provider = () => new WalletProvider({ networkPrefix })

const validMnemonic = 'virus shy bid eyebrow remove cool jungle seed elegant ball alarm asset reform champion hat scan act remember thumb cloth talent invite unable trouble';

test('WalletProvider#fromMnemonic: create keypair with valid mnemonic', async t => {
    const wallet = await provider().fromMnemonic({ mnemonic: validMnemonic });
    t.ok(wallet.publicKey);
    t.ok(wallet.secretKey);
    t.ok(wallet.address);
})

test('WalletProvider#fromMnemonic: create an instance of HDWallet with the default derivation path', async t => {
    const wallet = await provider().fromMnemonic({ mnemonic: validMnemonic });
    t.ok(wallet.derivationPath);
    t.ok(wallet.mnemonic);
})

test('WalletProvider#fromMnemonic: uses default derivation path that can be overriden', async t => {
    const wallet1 = await provider().fromMnemonic({ mnemonic: validMnemonic, derivationPath: defaultDerivationPath });
    const wallet2 = await provider().fromMnemonic({ mnemonic: validMnemonic });
    const wallet3 = await provider().fromMnemonic({ mnemonic: validMnemonic, derivationPath: nonDefaultDerivationPath });
    t.ok(wallet1.equals(wallet2));
    t.ok(!wallet1.equals(wallet3));
})