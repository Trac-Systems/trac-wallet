import address from './modules/address.js';
import hash from './modules/hash.js';
import mnemonic from './modules/mnemonic.js';
import nonce from './modules/nonce.js';
import signature from './modules/signature.js';

const sign = signature.sign;

// This is just for testing purposes. Remove later
console.log('Hashing a message using SHA-256:', hash.sha256('Hello, World!'));
console.log('Generating a mnemonic phrase:', mnemonic.generate());
console.log('Sanitizing a mnemonic phrase:', mnemonic.sanitize('abAndon Abandon abandon abandon abandOn abandon abandon abandon abandon abandon abandon about'));
console.log('Converting mnemonic to seed:', mnemonic.toSeed('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'));

export default {
    address,
    hash,
    mnemonic,
    nonce,
    signature,
    sign
};