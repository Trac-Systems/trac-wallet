import tracCryptoApi from 'trac-crypto-api';

/**
 * Bech32 human-readable part used for Trac testnet addresses.
 */
export const TRAC_NETWORK_MSB_TESTNET1_PREFIX = 'testtrac';

/**
 * Bech32 human-readable part used for Trac mainnet addresses.
 */
export const TRAC_NETWORK_MSB_MAINNET_PREFIX = 'trac';

/**
 * Public key size in bytes.
 */
export const TRAC_PUBLIC_KEY_SIZE = tracCryptoApi.address.PUB_KEY_SIZE;

/**
 * Secret/private key size in bytes.
 */
export const TRAC_SECRET_KEY_SIZE = tracCryptoApi.address.PRIV_KEY_SIZE;

/**
 * Signature size in bytes.
 */
export const TRAC_SIGNATURE_SIZE = tracCryptoApi.signature.SIZE;
