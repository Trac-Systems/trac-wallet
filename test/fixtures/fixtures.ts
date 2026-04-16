import tracCryptoApi from 'trac-crypto-api';
import b4a from 'b4a';
import { TRAC_NETWORK_MSB_TESTNET1_PREFIX } from '../../src/constants.ts';

export const mnemonic1 = 'bar same olive hurry place manage truck sleep banana wrist harvest bus clap prefer clarify copy leader jeans acoustic stairs cover echo reopen grow';
export const mnemonic2 = 'bundle dice bomb maze risk future deal force alpha blanket flush decline ski despair decline stand crunch stage mobile net sunset cool milk drip';
export const validMnemonic = 'virus shy bid eyebrow remove cool jungle seed elegant ball alarm asset reform champion hat scan act remember thumb cloth talent invite unable trouble';
export const mnemonic11Words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
export const nonSanitizedMnemonic = '    ' + mnemonic1.toUpperCase() + '    ';
export const addressPrefix = 'test';
export const testnetAddressPrefix = TRAC_NETWORK_MSB_TESTNET1_PREFIX;
export const nonDefaultDerivationPath = "m/44'/0'/0'/0'/0'"; // standard BIP44 path
export const defaultDerivationPath = "m/918'/0'/0'/0'"
export const testnetDerivationPath = tracCryptoApi.address.TESNET_DERIVATION_PATH;
export const invalidDerivationPath = 'm/4294967296'
export const validMnemonicExpectedTestnetAddress = 'testtrac166qlmx26m5pxfjfwpys87u9yrvqrfy6ya493lze59t67q8ufu23s2zn5xh';
export const secretKey = b4a.from(
    '2f45dec15453458c0f9fe5a26714b199d4a9ced62667ec954a1cf081fbd0386c644353180d4f86248841b043ff4c21d57956acefba62a156e11d746c7f1915c0',
    'hex'
)

export const isAddressValid = (address: string, prefix: string, pubKey: string) => {
    const isString = typeof address === 'string';
    const isNotEmpty = address.length > 0;
    const isValidPrefix = address.startsWith(prefix);
    const isValidPubKey = b4a.equals(tracCryptoApi.address.decode(address), b4a.from(pubKey, 'hex'));
    return isString && isNotEmpty && isValidPrefix && isValidPubKey;
}
