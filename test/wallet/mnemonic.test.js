import test from 'brittle';
import PeerWallet from '../../index.js';
import api from 'trac-crypto-api';

const validMnemonic = 'virus shy bid eyebrow remove cool jungle seed elegant ball alarm asset reform champion hat scan act remember thumb cloth talent invite unable trouble';
const faucetMnemonic = 'fiscal wing gift author sleep fantasy attack try soda behave viable undo come elbow lesson damage wolf festival circle crystal clarify antenna worry same';

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

test('PeerWallet: create keypair with valid mnemonic', async t => {
	const expectedAddress = 'testtrac1nad78sr02qyszx4d799qvj3n832rfc04gjrf0ywtynz9um38tjus938045'
	const wallet = new PeerWallet({ mnemonic: faucetMnemonic, networkPrefix: 'testtrac' });
	await wallet.ready;
	t.ok(wallet.publicKey);
	t.ok(wallet.secretKey);
	t.is(wallet.address, expectedAddress);
	
	const anotherDerivationPath = "m/919'/0'/0'/0'"
	const testnetWallet = new PeerWallet({ mnemonic: faucetMnemonic, networkPrefix: 'testtrac', derivationPath: anotherDerivationPath });
	await testnetWallet.ready;
	console.log('>>>> newAddress', testnetWallet.address)
	t.not(testnetWallet.address, expectedAddress);
});
