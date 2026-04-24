const b4a = require('b4a')
const crypto = require('hypercore-crypto')

const EMPTY = b4a.alloc(0)

const DEFAULT_SIGNATURE = getDefaultSignature()
const DEFAULT_HASH = getDefaultHash()
const HASH_BYTES = inferHashBytes()
const SHAPE = inferSignatureShape()
const PUBLIC_KEY_BYTES = SHAPE.publicKeyBytes
const SIGNATURE_BYTES = SHAPE.signatureBytes
const CORE_KEY_BYTES = inferCoreKeyBytes()

module.exports = {
  DEFAULT_SIGNATURE,
  DEFAULT_HASH,
  HASH_BYTES,
  PUBLIC_KEY_BYTES,
  SIGNATURE_BYTES,
  CORE_KEY_BYTES,
  sign,
  verify,
  isSupportedSignature
}

function getDefaultSignature() {
  if (typeof crypto.defaultSignature === 'function') return crypto.defaultSignature()
  if (typeof crypto.defaultSignature === 'string') return crypto.defaultSignature
  return 'ed25519'
}

function getDefaultHash() {
  if (typeof crypto.defaultHash === 'function') return crypto.defaultHash()
  if (typeof crypto.defaultHash === 'string') return crypto.defaultHash
  return 'blake2b'
}

function inferHashBytes() {
  return crypto.hash(EMPTY).byteLength
}

function inferSignatureShape() {
  const keyPair = crypto.keyPair()
  const signature = sign(EMPTY, keyPair, DEFAULT_SIGNATURE)
  return {
    publicKeyBytes: keyPair.publicKey.byteLength,
    signatureBytes: signature.byteLength
  }
}

function inferCoreKeyBytes() {
  if (typeof crypto.coreKeyBytes === 'function') return crypto.coreKeyBytes()
  if (typeof crypto.coreKeyBytes === 'number') return crypto.coreKeyBytes
  return HASH_BYTES
}

function sign(message, keyPair, signature = DEFAULT_SIGNATURE) {
  if (crypto.sign.length >= 3) return crypto.sign(message, keyPair.secretKey, signature)
  return crypto.sign(message, keyPair.secretKey)
}

function verify(message, signature, publicKey, signatureType = DEFAULT_SIGNATURE) {
  if (crypto.verify.length >= 4) return crypto.verify(message, signature, publicKey, signatureType)
  return crypto.verify(message, signature, publicKey)
}

function isSupportedSignature(signature) {
  if (typeof crypto.isSupportedSignature === 'function') {
    return crypto.isSupportedSignature(signature)
  }

  return signature === DEFAULT_SIGNATURE
}
