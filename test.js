import * as chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
import PeerWallet from './index.js';
import * as fs from 'fs';
import * as bip39 from 'bip39-mnemonic';
import sodium from 'sodium-native';

chai.use(chaiAsPromised)
const expect = chai.expect;

const buildWallet = (mnemonic) => {
    const newWallet = new PeerWallet({mnemonic : mnemonic});
    return newWallet;
}

describe('Wallet', () => {
    let wallet;

    beforeEach(async () => {
        wallet = new PeerWallet();
        await wallet.generateKeyPair(wallet.generateMnemonic());
    });

    describe('Mnemonic Generation', () => {
        it('should generate a valid mnemonic phrase', () => {
            const mnemonic = wallet.generateMnemonic();
            expect(mnemonic).to.be.a('string');
            expect(mnemonic.split(' ')).to.have.lengthOf(24);
            expect(bip39.validateMnemonic(mnemonic)).to.be.true;
        });

        it('should accept a valid mnemonic input', async () => {
            const validMnemonic = 'green ceiling yellow certain brass bottom east scorpion shove nasty business belt turkey target grow grunt stock glimpse man detail guitar goat front dose';
            const walletLocal1 = buildWallet(validMnemonic);
            const walletLocal2 = buildWallet();
            const walletLocal3 = buildWallet();

            expect(walletLocal1.publicKey).to.equal('9da26e25076b53adb370630f825917c23600117da83b7cbdca12332aac8c0f21');
            
            walletLocal2.generateKeyPairSync(validMnemonic);
            expect(walletLocal2.publicKey).to.equal('9da26e25076b53adb370630f825917c23600117da83b7cbdca12332aac8c0f21');
            
            await walletLocal3.generateKeyPair(validMnemonic);
            expect(walletLocal3.publicKey).to.equal('9da26e25076b53adb370630f825917c23600117da83b7cbdca12332aac8c0f21');
        });

        it('should throw an error for mnemonic containing less than 24 words', () => {
            const faultyMnemonic = 'green ceiling yellow certain brass bottom east scorpion shove nasty business belt turkey target grow grunt stock glimpse man detail guitar goat front';
            expect(() => buildWallet(faultyMnemonic)).to.throw('Invalid mnemonic');
        });

        it('should throw an error for mnemonic containing more than 24 words', () => {
            const faultyMnemonic = 'green ceiling yellow certain brass bottom east scorpion shove nasty business belt turkey target grow grunt stock glimpse man detail guitar goat front dose wagon';
            expect(() => buildWallet(faultyMnemonic)).to.throw('Invalid mnemonic');
        });

        it('should throw an error for mnemonic containing invalid word', async () => {
            const faultyMnemonic = 'green ceiling yellow certain brass bottom east scorpion shove nasty business belt turkey target grow grunt stock glimpse man detail guitar goat front invalid';
            expect(() => buildWallet(faultyMnemonic)).to.throw('Invalid mnemonic');
        });
    });

    describe('Key Pair Generation', () => {
        it('should generate a valid key pair', () => {
            const buf = Buffer.from(wallet.publicKey, 'hex')
            expect(buf).to.have.lengthOf(sodium.crypto_sign_PUBLICKEYBYTES);
        });

        it('should not generate keys with empty input', () => {
            const emptyWallet = new PeerWallet();
            expect(emptyWallet.publicKey).to.be.null;
        });

        it('should set a valid key pair', () => {
            const mnemonic = 'green ceiling yellow certain brass bottom east scorpion shove nasty business belt turkey target grow grunt stock glimpse man detail guitar goat front dose';
            const wallet1 = buildWallet(mnemonic);
            const wallet2 = new PeerWallet();
            const keyPair = {
                publicKey: "9da26e25076b53adb370630f825917c23600117da83b7cbdca12332aac8c0f21",
                secretKey: "538e9fdca456efec6fa208f99a7f74188f2dc31777b3a40980f22dec377b9a8a9da26e25076b53adb370630f825917c23600117da83b7cbdca12332aac8c0f21"
            };
            wallet2.keyPair = keyPair;
            expect(wallet2.publicKey.toString).to.equal(wallet1.publicKey.toString);

            const message = 'Hello, world!';
            const sig1 = wallet1.sign(message);
            const sig2 = wallet2.sign(message);
            expect(sig1).to.equal(sig2);
        });

        it('should throw an error for invalid key pair', () => {
            const newWallet = new PeerWallet();
            const invalidKeyPair = {
                publicKey: wallet.publicKey,
                secretKey: null
            };
            expect(() => newWallet.keyPair = invalidKeyPair).to.throw('Invalid key pair. Please provide a valid object with publicKey and secretKey');
        });
    });

    describe('Message Signing and Verification', () => {
        it('should sign and verify a message signature', () => {
            const message = 'Hello, world!';
            const signature = wallet.sign(message);
            const isValid = wallet.verify(signature, message, wallet.publicKey);
            expect(isValid).to.be.true;
        });

        it('should sign and verify a message signature with external private key', () => {
            const message = 'Hello, world!';
            const keyPair = {
                publicKey: "82444d4f8f042ec06bbfba4f0b01043a5fdb03e8a8481d740b964563c0f91868",
                secretKey: "38ff0b5c840266901050964857c54b9f92836bc60383277a788084192ea5a2dc82444d4f8f042ec06bbfba4f0b01043a5fdb03e8a8481d740b964563c0f91868"
            };
            const signature = wallet.sign(Buffer.from(message), Buffer.from(keyPair.secretKey, 'hex'));
            const isValid = wallet.verify(signature, message, keyPair.publicKey);
            expect(isValid).to.be.true;
        });

        it('should sign and verify a message signature where secret key is external and validation arguments are a Buffer type', () => {
            const message = 'Hello, world!';
            const keyPair = {
                publicKey: "82444d4f8f042ec06bbfba4f0b01043a5fdb03e8a8481d740b964563c0f91868",
                secretKey: "38ff0b5c840266901050964857c54b9f92836bc60383277a788084192ea5a2dc82444d4f8f042ec06bbfba4f0b01043a5fdb03e8a8481d740b964563c0f91868"
            };
            const signature = wallet.sign(Buffer.from(message), Buffer.from(keyPair.secretKey, 'hex'));
            const isValid = wallet.verify(Buffer.from(signature, 'hex'), Buffer.from(message), Buffer.from(keyPair.publicKey, 'hex'));
            expect(isValid).to.be.true;
        });

        it('should verify a signature even with empty key pair', () => {
            const emptyWallet = new PeerWallet();
            const message = 'Hello, world!';
            const signature = wallet.sign(message);
            const isValid = emptyWallet.verify(signature, message, wallet.publicKey);
            expect(isValid).to.be.true;
        });

        it('should not sign message when no keys are set', () => {
            const emptyWallet = new PeerWallet();
            expect(() => emptyWallet.sign('Hello, world!')).to.throw('No key pair found. Please, generate a key pair first');
        });
    });

    describe('Exporting Keys', () => {
        it('should export keys to a file', () => {
            const filePath = './wallet.json';
            wallet.exportToFile(filePath);
            const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
            expect(data.publicKey).to.equal(wallet.publicKey.toString('hex'));
            fs.unlinkSync(filePath); // Clean up the file after test
        });

        it('should be able to import keys from a file', () => {
            const filePath = './wallet.json';
            wallet.exportToFile(filePath);
            const newWallet = new PeerWallet();
            newWallet.importFromFile(filePath);
            expect(newWallet.publicKey.toString).to.equal(wallet.publicKey.toString);

            const message = 'Hello, world!';
            const sig1 = wallet.sign(message);
            const sig2 = newWallet.sign(message);
            expect(sig1).to.equal(sig2);

            fs.unlinkSync(filePath); // Clean up the file after test
        });

        it('should not export keypair when no keys are set', () => {
            const emptyWallet = new PeerWallet();
            expect(() => emptyWallet.exportToFile('./wallet.json')).to.throw('No key pair found');
        });
    });

    describe('Verify Only Mode', () => {
        it('should not generate key pair when isVerifyOnly is true', async () => {
            const errorMsg = 'This wallet is set to verify only. Please create a new wallet instance with a valid mnemonic to generate a key pair'
            const message = 'Hello, world!';
            const verifyOnlyWallet = new PeerWallet({ isVerifyOnly: true });
            const keyPair = {
                publicKey: "82444d4f8f042ec06bbfba4f0b01043a5fdb03e8a8481d740b964563c0f91868",
                secretKey: "38ff0b5c840266901050964857c54b9f92836bc60383277a788084192ea5a2dc82444d4f8f042ec06bbfba4f0b01043a5fdb03e8a8481d740b964563c0f91868"
            };

            expect(verifyOnlyWallet.isVerifyOnly).to.be.true;
            expect(verifyOnlyWallet.publicKey).to.be.null;

            expect(() => verifyOnlyWallet.keyPair = keyPair).to.throw(errorMsg);
            await expect(verifyOnlyWallet.generateKeyPair()).to.be.rejectedWith(errorMsg);
            expect(() => verifyOnlyWallet.sign(message)).to.throw(errorMsg);
            expect(() => verifyOnlyWallet.exportToFile('./wallet.json')).to.throw('No key pair found');
        });

        it('should verify a message signature when isVerifyOnly is true', () => {
            const message = 'Hello, world!';
            const signature = wallet.sign(message);
            const verifyOnlyWallet = new PeerWallet({ isVerifyOnly: true });
            const isValid = verifyOnlyWallet.verify(signature, message, wallet.publicKey);
            expect(isValid).to.be.true;
        });
    });
});