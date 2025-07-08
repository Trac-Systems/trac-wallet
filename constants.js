import sodium from 'sodium-native';

export const RANDOM_BUFFER_SIZE = 32;
export const ENCRYPTION_KEY_BYTES = sodium.crypto_secretbox_KEYBYTES;
export const TRAC_NETWORK_MAINNET_PREFIX = 'trac';