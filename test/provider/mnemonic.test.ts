import { test } from 'brittle';
import { WalletProvider } from '../../src/index.ts';
import { networkPrefix, defaultDerivationPath, nonDefaultDerivationPath, mnemonic11Words, invalidDerivationPath } from '../fixtures/fixtures.ts';

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
    t.is(wallet.derivationPath, defaultDerivationPath);
    t.ok(wallet.mnemonic);
})

test('WalletProvider#fromMnemonic: uses default derivation path that can be overriden', async t => {
    const wallet1 = await provider().fromMnemonic({ mnemonic: validMnemonic });
    const wallet2 = await provider().fromMnemonic({ mnemonic: validMnemonic });
    const wallet3 = await provider().fromMnemonic({ mnemonic: validMnemonic, derivationPath: nonDefaultDerivationPath });
    t.ok(wallet1.equals(wallet2));
    t.ok(!wallet1.equals(wallet3));
})

test('WalletProvider#fromMnemonic: throws on invalid derivation path', async t => {
    try {
        await provider().fromMnemonic({ mnemonic: validMnemonic, derivationPath: invalidDerivationPath });
        t.fail('Expected error not thrown');
    } catch (error: any) {
        t.ok(error.message.includes('Invalid segment'), 'throws for invalid derivation path');
    }
})

test('WalletProvider#fromMnemonic: throws on invalid mnemonic (11 words)', async t => {
    try {
        await provider().fromMnemonic({ mnemonic: mnemonic11Words });
        t.fail('Expected error not thrown');
    } catch (error: any) {
        t.is(error.message, 'Invalid secret key format. Please provide a valid hex string');
    }
})
