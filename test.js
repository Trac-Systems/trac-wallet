import { expect } from 'chai';
import { Wallet } from './index.js';
import * as fs from 'fs';
import * as bip39 from 'bip39';
import sodium from 'sodium-native';

describe('Wallet', () => {
    let wallet;

    beforeEach(() => {
        wallet = new Wallet();
        wallet.generateKeyPair(wallet.generateMnemonic());
    });

    describe('Mnemonic Generation', () => {
        it('should generate a valid mnemonic phrase', () => {
            const mnemonic = wallet.generateMnemonic();
            expect(mnemonic).to.be.a('string');
            expect(mnemonic.split(' ')).to.have.lengthOf(12);
            expect(bip39.validateMnemonic(mnemonic)).to.be.true;
        });

        it('should accept a valid mnemonic input', () => {
            const validMnemonic = 'session attitude weekend sign collect mobile return vacuum pool afraid wagon client';
            const walletLocal = new Wallet(validMnemonic);
            expect(walletLocal.publicKey).to.equal('82444d4f8f042ec06bbfba4f0b01043a5fdb03e8a8481d740b964563c0f91868');
        });

        it('should throw an error for mnemonic containing less than 12 words', () => {
            const faultyMnemonic = 'session attitude weekend sign collect mobile return vacuum pool afraid wagon';
            expect(() => new Wallet(faultyMnemonic)).to.throw('Invalid mnemonic');
        });

        it('should throw an error for mnemonic containing more than 12 words', () => {
            const faultyMnemonic = 'session attitude weekend sign collect mobile return vacuum pool afraid wagon client extra';
            expect(() => new Wallet(faultyMnemonic)).to.throw('Invalid mnemonic');
        });

        it('should throw an error for mnemonic containing invalid word', () => {
            const faultyMnemonic = 'session attitude weekend sign collect mobile return vacuum pool afraid wagon invalid';
            expect(() => new Wallet(faultyMnemonic)).to.throw('Invalid mnemonic');
        });
    });

    describe('Key Pair Generation', () => {
        it('should generate a valid key pair', () => {
            const buf = Buffer.from(wallet.publicKey, 'hex')
            expect(buf).to.have.lengthOf(sodium.crypto_sign_PUBLICKEYBYTES);
        });

        it('should not generate keys with empty input', () => {
            const emptyWallet = new Wallet();
            expect(emptyWallet.publicKey).to.be.null;
        });

        it('should set a valid key pair', () => {
            const mnemonic = 'session attitude weekend sign collect mobile return vacuum pool afraid wagon client';
            const wallet1 = new Wallet(mnemonic);
            const wallet2 = new Wallet();
            const keyPair = {
                publicKey: "82444d4f8f042ec06bbfba4f0b01043a5fdb03e8a8481d740b964563c0f91868",
                secretKey: "38ff0b5c840266901050964857c54b9f92836bc60383277a788084192ea5a2dc82444d4f8f042ec06bbfba4f0b01043a5fdb03e8a8481d740b964563c0f91868"
            };
            wallet2.keyPair = keyPair;
            expect(wallet2.publicKey.toString).to.equal(wallet1.publicKey.toString);

            const message = 'Hello, world!';
            const sig1 = wallet1.sign(message);
            const sig2 = wallet2.sign(message);
            expect(sig1).to.equal(sig2);
        });

        it('should throw an error for invalid key pair', () => {
            const newWallet = new Wallet();
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

        it('should verify a signature even with empty key pair', () => {
            const emptyWallet = new Wallet();
            const message = 'Hello, world!';
            const signature = wallet.sign(message);
            const isValid = emptyWallet.verify(signature, message, wallet.publicKey);
            expect(isValid).to.be.true;
        });

        it('should not sign message when no keys are set', () => {
            const emptyWallet = new Wallet();
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
            const newWallet = new Wallet();
            newWallet.importFromFile(filePath);
            expect(newWallet.publicKey.toString).to.equal(wallet.publicKey.toString);

            const message = 'Hello, world!';
            const sig1 = wallet.sign(message);
            const sig2 = newWallet.sign(message);
            expect(sig1).to.equal(sig2);

            fs.unlinkSync(filePath); // Clean up the file after test
        });

        it('should not export keypair when no keys are set', () => {
            const emptyWallet = new Wallet();
            expect(() => emptyWallet.exportToFile('./wallet.json')).to.throw('No key pair found');
        });
    });
});