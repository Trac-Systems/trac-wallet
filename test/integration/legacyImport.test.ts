import test from 'brittle';
import b4a from 'b4a';
import fs from 'fs';
import { join } from 'path';
import { IHDWallet } from '../../src/index.ts';
import { importFromFile } from '../../src/exporter.ts';
// @ts-ignore Legacy package fixture module has no TypeScript declarations.
import LegacyWallet from '../../node_modules/trac-wallet/index.js';
// @ts-ignore Legacy package fixture module has no TypeScript declarations.
import { derivationPath, mnemonic1, networkPrefix } from '../../node_modules/trac-wallet/test/fixtures/fixtures.js';

const password = b4a.from('testpassword');
const filePath = join('./legacy-test-keyfile.json');
const cleanup = () => fs.existsSync(filePath) && fs.unlinkSync(filePath)

test('integration: imports keystore exported by trac-wallet@1.0.3', async t => {
    t.teardown(cleanup);

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
