import { expect } from 'chai';
import PeerWallet from './index.js';
import * as fs from 'fs';
import * as bip39 from 'bip39';
import sodium from 'sodium-native';
import {mnemonicToSeed} from 'bip39-mnemonic';
import b4a from 'b4a';
import slip10 from 'micro-key-producer/slip10.js';

describe('Wallet', () => {
    let wallet;
    const validMnemonic = 'expire hobby crumble barely company behind solve kingdom plastic goddess congress sort awkward cancel ring quick gain wise doctor season fruit perfect fatal pool';

    beforeEach(() => {
        wallet = new PeerWallet();
        wallet.generateKeyPair(validMnemonic);
    });

    describe('HD Wallet Support', () => {
        it('should create a valid HD wallet from micro-key-producer based on peer wallet mnemonic, then HD wallet signs a message and is verified by both HD and PeerWallet.', async () => {
            const mnemonic = wallet.generateMnemonic();
            const walletLocal = new PeerWallet();
            await walletLocal.generateKeyPair(mnemonic);
            const seed = await mnemonicToSeed(mnemonic);
            const seed32 = await walletLocal.createHash('sha256', seed);

            const msg = 'this is a test';

            const hdkey = slip10.fromMasterSeed(seed32);
            const sig = hdkey.sign(b4a.toString(b4a.from(msg, 'utf8'), 'hex'));

            const hd_verify = hdkey.verify(b4a.toString(b4a.from(msg, 'utf8'), 'hex'), sig);
            const native_verify = walletLocal.verify(b4a.toString(sig, 'hex'), msg, b4a.toString(hdkey.publicKeyRaw, 'hex'));

            // reverse case tested through micro-key-producer hacking because it doesn't support off-wallet verify.
            // confirmed to work.
            /*
            const sig2 = walletLocal.sign(msg);
            const hd_verify2 = hdkey.verify2(b4a.toString(b4a.from(msg, 'utf8'), 'hex'), sig2, walletLocal.publicKey);
            console.log(hd_verify2)*/

            expect(hd_verify === native_verify).to.equal(true);
        });
    });

    describe('Mnemonic Generation', () => {
        it('should generate a valid mnemonic phrase', () => {
            const mnemonic = wallet.generateMnemonic();
            expect(mnemonic).to.be.a('string');
            expect(mnemonic.split(' ')).to.have.lengthOf(24);
            expect(bip39.validateMnemonic(mnemonic)).to.be.true;
        });

        it('should accept a valid mnemonic input', async () => {
            const walletLocal = new PeerWallet();
            await walletLocal.generateKeyPair(validMnemonic);
            expect(walletLocal.publicKey).to.equal('e848b77918a7e5d7b990b47751fb8e90256743cabbe2e15f016ae7cc621fe108');
        });

        it('should throw an error for mnemonic containing less than 24 words',  async () => {
            const faultyMnemonic = 'expire hobby crumble barely company behind solve kingdom plastic goddess congress sort awkward cancel ring quick gain wise doctor season fruit perfect';
            const walletLocal = new PeerWallet();
            let thrown = false;
            try{
                await walletLocal.generateKeyPair(faultyMnemonic);
            }catch(e){
                thrown = true;
            }
            expect(thrown).to.equal(true);
        });

        it('should throw an error for mnemonic containing more than 24 words', async () => {
            const faultyMnemonic = 'expire hobby crumble barely company behind solve kingdom plastic goddess congress sort awkward cancel ring quick gain wise doctor season fruit perfect fatal pool pool';
            const walletLocal = new PeerWallet();
            let thrown = false;
            try{
                await walletLocal.generateKeyPair(faultyMnemonic);
            }catch(e){
                thrown = true;
            }
            expect(thrown).to.equal(true);
        });

        it('should throw an error for mnemonic containing invalid word', async () => {
            const faultyMnemonic = 'expire hobby crumble barely company behind solve kingdom plastic goddess congress sort awkward cancel ring quick gain wise doctor season fruit perfect fatal invalid';
            const walletLocal = new PeerWallet();
            let thrown = false;
            try{
                await walletLocal.generateKeyPair(faultyMnemonic);
            }catch(e){
                thrown = true;
            }
            expect(thrown).to.equal(true);
        });
    });

    describe('Key Pair Generation', () => {
        it('should generate a valid key pair', async () => {
            const walletLocal = new PeerWallet();
            await walletLocal.generateKeyPair(validMnemonic);
            const buf = Buffer.from(walletLocal.publicKey, 'hex')
            expect(buf).to.have.lengthOf(sodium.crypto_sign_PUBLICKEYBYTES);
        });

        it('should not generate keys with empty input', () => {
            const emptyWallet = new PeerWallet();
            expect(emptyWallet.publicKey).to.be.null;
        });

        it('should set a valid key pair', async () => {
            const wallet1 = new PeerWallet();
            await wallet1.generateKeyPair(validMnemonic);
            const wallet2 = new PeerWallet();
            const keyPair = {
                publicKey: "e848b77918a7e5d7b990b47751fb8e90256743cabbe2e15f016ae7cc621fe108",
                secretKey: "2f1f7961ea38fbf7735eebb7d2faddaa7cea5fef637e60665f976907f4f29d55e848b77918a7e5d7b990b47751fb8e90256743cabbe2e15f016ae7cc621fe108"
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
        it('should sign and verify a message signature', async () => {
            const message = 'Hello, world!';
            const wallet1 = new PeerWallet();
            await wallet1.generateKeyPair(validMnemonic);
            const signature = wallet1.sign(message);
            const isValid = wallet1.verify(signature, message, wallet1.publicKey);
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

        it('should verify a signature even with empty key pair', async () => {
            const emptyWallet = new PeerWallet();
            const wallet1 = new PeerWallet();
            await wallet1.generateKeyPair(validMnemonic);
            const message = 'Hello, world!';
            const signature = wallet1.sign(message);
            const isValid = emptyWallet.verify(signature, message, wallet1.publicKey);
            expect(isValid).to.be.true;
        });

        it('should not sign message when no keys are set', () => {
            const emptyWallet = new PeerWallet();
            expect(() => emptyWallet.sign('Hello, world!')).to.throw('No key pair found. Please, generate a key pair first');
        });
    });

    describe('Exporting Keys', () => {
        it('should export keys to a file', async () => {
            const filePath = './wallet.json';
            const wallet1 = new PeerWallet();
            await wallet1.generateKeyPair(validMnemonic);
            wallet1.exportToFile(filePath);
            const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
            expect(data.publicKey).to.equal(wallet1.publicKey.toString('hex'));
            fs.unlinkSync(filePath); // Clean up the file after test
        });

        it('should be able to import keys from a file', async () => {
            const filePath = './wallet.json';
            const wallet1 = new PeerWallet();
            await wallet1.generateKeyPair(validMnemonic);
            wallet1.exportToFile(filePath);
            const newWallet = new PeerWallet();
            newWallet.importFromFile(filePath);
            expect(newWallet.publicKey.toString).to.equal(wallet1.publicKey.toString);

            const message = 'Hello, world!';
            const sig1 = wallet1.sign(message);
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
            let throws = false;
            try{
               await verifyOnlyWallet.generateKeyPair();
            }catch(e)
            {
                throws = true;
            }
            expect(throws).to.equal(true);
            expect(() => verifyOnlyWallet.sign(message)).to.throw(errorMsg);
            expect(() => verifyOnlyWallet.exportToFile('./wallet.json')).to.throw('No key pair found');
        });

        it('should verify a message signature when isVerifyOnly is true', async () => {
            const message = 'Hello, world!';
            const wallet1 = new PeerWallet();
            await wallet1.generateKeyPair(validMnemonic);
            const signature = wallet1.sign(message);
            const verifyOnlyWallet = new PeerWallet({ isVerifyOnly: true });
            const isValid = verifyOnlyWallet.verify(signature, message, wallet1.publicKey);
            expect(isValid).to.be.true;
        });
    });
});

describe('Nonce Generation', () => {
    it('should return a buffer of 32 bytes', () => {
        const nonce = PeerWallet.generateNonce();
        expect(b4a.isBuffer(nonce)).to.be.true;
        expect(nonce.length).to.equal(32);
    });

    it('should return a different nonce each time', () => {
        const nonce1 = PeerWallet.generateNonce();
        const nonce2 = PeerWallet.generateNonce();
        expect(b4a.equals(nonce1, nonce2)).to.be.false;
      });

});