import tracCryptoApi from 'trac-crypto-api';
import b4a from 'b4a';

export const mnemonic1 = 'bar same olive hurry place manage truck sleep banana wrist harvest bus clap prefer clarify copy leader jeans acoustic stairs cover echo reopen grow';
export const mnemonic2 = 'bundle dice bomb maze risk future deal force alpha blanket flush decline ski despair decline stand crunch stage mobile net sunset cool milk drip';
export const nonSanitizedMnemonic = '    ' + mnemonic1.toUpperCase() + '    ';
export const networkPrefix = 'test';
export const nonDefaultDerivationPath = "m/44'/0'/0'/0'/0'"; // standard BIP44 path
export const defaultDerivationPath = "m/918'/0'/0'/0'"

export const isAddressValid = (address: string, prefix: string, pubKey: string) => {
    const isString = typeof address === 'string';
    const isNotEmpty = address.length > 0;
    const isValidPrefix = address.startsWith(prefix);
    const isValidPubKey = b4a.equals(tracCryptoApi.address.decode(address), b4a.from(pubKey, 'hex'));
    return isString && isNotEmpty && isValidPrefix && isValidPubKey;
}
