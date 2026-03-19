import test from 'brittle';
import b4a from 'b4a';
import fs from 'fs';
import { join } from 'path';
import { IHDWallet } from '../../src/index.ts';
import { importFromFile } from '../../src/exporter.ts';

// Below is stuff by chatgpt to ensure this thing worked on the CI.
const legacyPackageRoot = import.meta.url.includes('/.test-build/')
    ? '../../../node_modules/trac-wallet/'
    : '../../node_modules/trac-wallet/';
const legacyWalletModule = new URL(`${legacyPackageRoot}index.js`, import.meta.url).href;
const legacyFixturesModule = new URL(`${legacyPackageRoot}test/fixtures/fixtures.js`, import.meta.url).href;
// @ts-ignore Legacy package fixture module has no TypeScript declarations.
const { default: LegacyWallet } = await import(legacyWalletModule);
// @ts-ignore Legacy package fixture module has no TypeScript declarations.
const { derivationPath, mnemonic1, networkPrefix } = await import(legacyFixturesModule);

const password = b4a.from('testpassword');
const createFilePath = () => join('.', `legacy-test-keyfile-${Date.now()}-${Math.random().toString(16).slice(2)}.json`);
const cleanup = (filePath: string) => fs.existsSync(filePath) && fs.unlinkSync(filePath)

test('integration: imports keystore exported by trac-wallet@1.0.3', async t => {
    const filePath = createFilePath();
    t.teardown(() => cleanup(filePath));

    const legacyWallet = new LegacyWallet({ mnemonic: mnemonic1, derivationPath, networkPrefix });
    await legacyWallet.ready;
    legacyWallet.exportToFile(filePath, password);

    const importedWallet = await importFromFile(filePath, password, networkPrefix) as IHDWallet;

    t.ok(b4a.equals(importedWallet.publicKey, legacyWallet.publicKey));
    t.ok(b4a.equals(importedWallet.secretKey, legacyWallet.secretKey));
    t.is(importedWallet.address, legacyWallet.address);
    t.is(importedWallet.mnemonic, legacyWallet.mnemonic);
    t.is(importedWallet.derivationPath, legacyWallet.derivationPath);
});
