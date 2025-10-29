import PeerWallet from './index.js';
import readline from 'readline';

async function main() {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });

    const wallet = new PeerWallet();
    try {
        await wallet.initKeyPair('./test-peerwallet.key', rl);
        console.log('\nWallet loaded!');
        console.log('Address:', wallet.address);
        console.log('Public Key:', wallet.publicKey?.toString('hex'));
        console.log('Derivation Path:', wallet.derivationPath);
    } catch (err) {
        console.error('Error:', err.message);
    } finally {
        await wallet.close();
        rl.close();
    }
}

main();
