import test from 'brittle';
import { WalletProvider } from '../../src/index.ts';
import b4a from 'b4a';
import tracCryptoApi from 'trac-crypto-api';
import { addressPrefix, nonDefaultDerivationPath } from '../fixtures/fixtures.ts';

const provider = () => new WalletProvider({ addressPrefix })
const asHex = (value: Buffer | Uint8Array): string => b4a.toString(value, 'hex')

async function randomKeyPair() {
    const mnemonic = tracCryptoApi.mnemonic.generate();
    // @ts-expect-error (should be removed after the js-docs are corrected on trac-crypto-api)
    const kp = await tracCryptoApi.address.generate(addressPrefix, mnemonic, nonDefaultDerivationPath);
    return { publicKey: kp.publicKey, secretKey: kp.secretKey, address: kp.address };
}

test('WalletProvider#fromSecretKey: creates wallet from valid keypair', async t => {
    const { publicKey, secretKey, address } = await randomKeyPair();
    const wallet = await provider().fromSecretKey(asHex(secretKey));
    t.ok(b4a.equals(wallet.publicKey, publicKey), 'publicKey matches');
    t.ok(b4a.equals(wallet.secretKey, secretKey), 'secretKey matches');
    t.is(wallet.address, address, 'address matches');
});

test('WalletProvider#fromSecretKey: throws on invalid secretKey', async t => {
    const secretKey = b4a.alloc(10); // invalid size
    try {
        await provider().fromSecretKey(asHex(secretKey));
        t.fail('Expected error not thrown');
    }
    catch {
        t.pass('throws on invalid secretKey');
    }
});
