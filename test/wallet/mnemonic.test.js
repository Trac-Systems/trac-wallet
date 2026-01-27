import test from 'brittle';
import PeerWallet from '../../index.js';
import api from 'trac-crypto-api';

const validMnemonic = 'virus shy bid eyebrow remove cool jungle seed elegant ball alarm asset reform champion hat scan act remember thumb cloth talent invite unable trouble';

test('PeerWallet: valid mnemonic returns true for validation', async t => {
	const wallet = new PeerWallet();
	const mnemonic = api.mnemonic.generate();
	t.ok(wallet.sanitizeMnemonic(mnemonic) === mnemonic);
	t.ok(wallet.sanitizeMnemonic(validMnemonic) === validMnemonic);
});

test('PeerWallet: create keypair with valid mnemonic', async t => {
	const wallet = new PeerWallet({ mnemonic: validMnemonic });
	await wallet.ready;
	t.ok(wallet.publicKey);
	t.ok(wallet.secretKey);
	t.ok(wallet.address);
});
