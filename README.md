# ED25519 Key Generator

This project provides a `Wallet` class that can generate and store ED25519 keys, sign messages, and verify signatures. It also includes functionality to export keys to a JSON file.

## Installation

To install the necessary dependencies, run:

```bash
npm install
```

## Usage

### Generating a Wallet

You can create a new wallet with a randomly generated mnemonic phrase:

```javascript
import { Wallet } from './index.js';

const wallet = new Wallet();
const mnemonic = wallet.generateMnemonic() // creates a randomly generated mnemonic phrase containing 12 words
wallet.generateKeypair(mnemonic) // Generates a keypair using the provided mnemonic and stores it internally

console.log(mnemonic);
console.log(wallet.publicKey.toString('hex')); // Prints the public key
```

You can also create a wallet with a specific mnemonic phrase:

```javascript
const mnemonic = 'session attitude weekend sign collect mobile return vacuum pool afraid wagon client';
const wallet = new Wallet(mnemonic);
console.log(wallet.publicKey.toString('hex')); // Prints the public key
```

### Signing and Verifying Messages

You can sign a message with the wallet's secret key and verify the signature with the public key:

```javascript
const message = 'Hello, world!';
const signature = wallet.signMessage(message);
const isValid = wallet.verifySignature(message, signature, wallet.publicKey);
console.log(isValid); // Prints true if the signature is valid
```

### Exporting Keys to a File

You can export the wallet's keys to a JSON file:

```javascript
const filePath = './wallet.json';
wallet.exportToFile(filePath);
```

## Running Tests

To run the tests, use the following command:

```bash
npx mocha test.js
```

## License

TODO