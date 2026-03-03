import test from 'brittle';

async function runTests() {
  const harness = test as any;
  harness.pause();
  await import('./wallet/verifySign.test.ts');
  await import('./provider/mnemonic.test.ts');
  await import('./provider/fromSecretKey.test.ts');
  harness.resume();
}

await runTests();
