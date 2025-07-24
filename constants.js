import sodium from 'sodium-native';

export const TRAC_PUB_KEY_SIZE = sodium.crypto_sign_PUBLICKEYBYTES;
export const TRAC_PRIV_KEY_SIZE = sodium.crypto_sign_SECRETKEYBYTES;
export const ENCRYPTION_KEY_BYTES = sodium.crypto_secretbox_KEYBYTES;
export const RANDOM_BUFFER_SIZE = 32;

export const TRAC_NETWORK_MSB_MAINNET_PREFIX = 'trac';
export const BECH32M_HRP_SIZE = TRAC_NETWORK_MSB_MAINNET_PREFIX.length + 1; // +1 for the separator character '1'
export const BECH32M_DATA_SIZE = Math.ceil(TRAC_PUB_KEY_SIZE * 8 / 5);
export const BECH32M_CHECKSUM_SIZE = 6;
export const TRAC_ADDRESS_SIZE = BECH32M_HRP_SIZE + BECH32M_DATA_SIZE + BECH32M_CHECKSUM_SIZE;