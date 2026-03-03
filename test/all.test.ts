import { default as test } from 'brittle';

async function runTests() {
  test.pause();
  await import('./wallet/verify_sign.test.js');
  test.resume();
}

await runTests();
