import { sodium } from './env.js'
import b4a from 'b4a';
import { validateMnemonic, normalizeMnemonic } from 'bip39-mnemonic';

export function mnemonicToSeedSync (mnemonic, passphrase = '') {
  mnemonic = normalizeMnemonic(mnemonic)

  if (!validateMnemonic(mnemonic)) {
    throw new Error('Invalid mnemonic')
  }

  const input = b4a.from(mnemonic)
  const salt = b4a.from('mnemonic' + passphrase)

  const output = b4a.alloc(64)

  sodium.extension_pbkdf2_sha512(
    output,
    input,
    salt,
    2048,
    64
  )

  return output
}