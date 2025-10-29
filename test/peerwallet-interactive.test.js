import PeerWallet from '../index.js';
import readline from 'readline';
import tty from 'tty';

async function main() {
    const rl = readline.createInterface({
        input: new tty.ReadStream(0),
        output: new tty.WriteStream(1)
    });

    const keyStorePath = './wallet.key';

    const wallet = new PeerWallet();
    await wallet.ready;
    try {
        await wallet.initKeyPair(keyStorePath); // Optionally, we can pass a custom readline interface by using the commented line below instead
        // await wallet.initKeyPair(keyStorePath, rl);

        console.log('\n\n');
        console.log('Address:', wallet.address);
        console.log('Public Key:', wallet.publicKey?.toString('hex'));
        console.log('Derivation Path:', wallet.derivationPath);
    } catch (err) {
        console.error('Error:', err.message);
    } finally {
        await wallet.close();
        rl.close();
    }
    console.log('Done.');
}

main();
