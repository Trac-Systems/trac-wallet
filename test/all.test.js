import { default as test } from 'brittle';

async function runTests() {
    test.pause();
    await import('./wallet/address.test.js');
    await import('./wallet/sign_verify.test.js');
    test.resume();
}

await runTests();