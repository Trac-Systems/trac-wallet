import { default as test } from 'brittle';

async function runTests() {
    test.pause();
    await import('./api_exposed.test.js');
    await import('./export_import.test.js');
    await import('./from_keypair.test.js');
    await import('./mnemonic.test.js');
    await import('./sign_verify.test.js');
    test.resume();
}

await runTests();