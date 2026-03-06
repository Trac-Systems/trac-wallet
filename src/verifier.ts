import { IVerifier, PublicKey, Message, Signature } from "./types/index.ts"
import tracCryptoApi from "trac-crypto-api"
import b4a from 'b4a'
import { TRAC_PUBLIC_KEY_SIZE } from "./constants.ts"

const validate = (publicKey: PublicKey) => {
    if (!b4a.isBuffer(publicKey) || publicKey.length !== TRAC_PUBLIC_KEY_SIZE) {
        throw new Error(
            `Invalid public key. Expected a Buffer of length ${TRAC_PUBLIC_KEY_SIZE}, got ${publicKey.length}`
        );
    }
}

export class Verifier implements IVerifier {
    #publicKey: PublicKey

    constructor(publicKey: PublicKey) {
        validate(publicKey)
        this.#publicKey = publicKey
    }

    get publicKey() {
        return this.#publicKey;
    }

    /**
     * Verifies a signature using the internal public key.
     * @param {Message} signature - The signature to verify.
     * @param {Signature} message - The message to verify.
     * @returns {boolean} true if valid, false otherwise.
     */
    verify(signature: Signature, message: Message): boolean {
        return tracCryptoApi.signature.verify(signature, message, this.#publicKey)
    }
}
