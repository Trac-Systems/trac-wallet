import PeerWallet from './index.js';
import b4a from 'b4a';

async function main() {

    // Please, add this to the wallet index.js. Currently mnemonic is stored privatelly:
    /*
    get mnemonic() {
        return this.#keyPair.mnemonic;
    }
    */

    const filePath = './wallet.key'; // NOTE: Change this to your key file path

    const wallet = new PeerWallet();
    await wallet.ready;
    await wallet.importFromFile(filePath); // Assuming no password (as MSB currently behaves)

    console.log('Address:', wallet.address);
    console.log('Public Key:', b4a.toString(wallet.publicKey, 'hex'));
    console.log('Secret Key:', b4a.toString(wallet.secretKey, 'hex'));
    console.log('Mnemonic:', wallet.mnemonic);
    console.log('Derivation Path:', wallet.derivationPath);


    // Just a check to verify that it is recovereable from mnemonic:
    const recoveredWallet = new PeerWallet({ mnemonic: wallet.mnemonic, derivationPath: wallet.derivationPath });
    await recoveredWallet.ready;

    console.log('\nRecovered Wallet:');
    console.log('Address:', recoveredWallet.address);
    console.log('Public Key:', b4a.toString(recoveredWallet.publicKey, 'hex'));
    console.log('Secret Key:', b4a.toString(recoveredWallet.secretKey, 'hex'));

    console.log('\nMatch check:');
    console.log('Address match:', wallet.address === recoveredWallet.address);
    console.log('Public Key match:', b4a.equals(wallet.publicKey, recoveredWallet.publicKey));
    console.log('Secret Key match:', b4a.equals(wallet.secretKey, recoveredWallet.secretKey));
}

main().catch(console.error);
