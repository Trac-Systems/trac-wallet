import { default as test } from 'brittle';

async function runTests() {
    test.pause();
    await import('./generation.test.js');
    await import('./derivation.test.js');
    test.resume();
}

await runTests();