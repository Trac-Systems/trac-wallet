import { blake3 } from "@tracsystems/blake3"
import b4a from 'b4a'
import sodium from 'sodium-native'

const TYPE_MAPS = {
  'sha1': 'SHA-1',
  'sha384': 'SHA-384',
  'sha512': 'SHA-512'
}

const toSubtleType = type => {
  if (Object.keys(TYPE_MAPS).includes(type?.toLowerCase()))
    return type.toLowerCase()[type?.toLowerCase()]

  throw new Error('Unsupported algorithm.')  
}

const sha256 = message => {
  const out = b4a.alloc(sodium.crypto_hash_sha256_BYTES)
  sodium.crypto_hash_sha256(out, b4a.from(message))
  return out
}

// default size is 32
const defaultHash = async (message, size) => {
  const messageBytes = b4a.from(message)
  const hashBytes = await blake3(messageBytes, size)
  return b4a.from(hashBytes, 'hex')
}

export const hash = async (message, type = 'blake3') => {
  if (type === 'sha256') {
    return sha256(message)
  } else if (type === 'blake3') {
    return defaultHash(message)
  }

  if (global.Pear !== undefined) {
    const encoder = new TextEncoder()
    const data = encoder.encode(message)
    const hash = await crypto.subtle.digest(toSubtleType(type), data)
    const hashArray = b4a.from(new Uint8Array(hash))
    return hashArray
  } else {
    return b4a.from(crypto.createHash(type).update(message).digest('hex'), 'hex'); // TODO: Implement tests for this part of the code
  }
}
