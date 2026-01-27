import { default as test } from 'brittle';

async function runTests() {
    test.pause();
    await import('./address/address.test.js');
    await import('./wallet/wallet.test.js');
    test.resume();
}

await runTests();