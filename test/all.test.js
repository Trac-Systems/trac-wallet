import { default as test } from 'brittle';

async function runTests() {
    test.pause();
    await import('./wallet/address.test.js');
    await import('./wallet/sign_verify.test.js');
    await import('./wallet/export_import.test.js');
    await import('./wallet/hd_wallet_support.test.js');
    test.resume();
}

await runTests();