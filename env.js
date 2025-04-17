export let sodium;
import crypto from 'crypto';
const isBrowser = typeof window !== 'undefined' && typeof window.document !== 'undefined';

async function loadSodium() {
    if (!sodium) {
        if (!isBrowser) {
            const mod = await import('sodium-native');
            sodium = mod.default || mod;
        } else {
            const mod = await import('libsodium-wrappers');
            await mod.ready;
            sodium = mod.default || mod;
        }
    }
    return sodium;
}
await loadSodium();

function sha256Browser(message, outputBuffer) {
    const hash = crypto.createHash('sha256').update(message).digest();
    hash.copy(outputBuffer);
}

function sha256Native(messageBuffer, outputBuffer) {
    sodium.crypto_hash_sha256(outputBuffer, messageBuffer);
}

const sha256Impl = isBrowser && sha256Browser || sha256Native;

export function sha256(message, outputBuffer) {
    return sha256Impl(message, outputBuffer);
}