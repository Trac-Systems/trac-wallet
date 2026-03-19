import test from 'brittle';

async function runTests() {
  const harness = test as any;
  harness.pause();
  await import('./wallet/verifySign.test.ts');
  await import('./wallet/equal.test.ts');
  await import('./wallet/asJson.test.ts');
  await import('./verifier/verify.test.ts');
  await import('./provider/mnemonic.test.ts');
  await import('./provider/fromSecretKey.test.ts');
  await import('./provider/generate.test.ts');
  await import('./exporter/importExport.test.ts');
  await import('./integration/legacyImport.test.ts');
  harness.resume();
}

await runTests();
