import { default as test } from 'brittle';

async function runTests() {
  (test as any).pause();
  await import('./wallet/verify_sign.test.js');
  (test as any).resume();
}

await runTests();
