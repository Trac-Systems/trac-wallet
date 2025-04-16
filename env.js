export let sodium;
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