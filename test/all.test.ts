import test from 'brittle';

async function runTests() {
  const harness = test as any;
  harness.pause();
  await import('./wallet/verify_sign.test.ts');
  await import('./provider/mnemonic.test.ts');
  harness.resume();
}

await runTests();
