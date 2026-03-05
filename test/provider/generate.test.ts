import { test } from 'brittle';
import { WalletProvider } from '../../src/index.ts';
import { networkPrefix } from '../fixtures/fixtures.js';

const provider = () => new WalletProvider({ networkPrefix })

test('WalletProvider#generate: creates a wallet', async t => {
    const wallet = await provider().generate('0123456789abcdef');
    t.ok(wallet);
});
