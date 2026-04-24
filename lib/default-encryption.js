const sodium = require('sodium-universal')
const c = require('compact-encoding')
const b4a = require('b4a')
const { DEFAULT_ENCRYPTION } = require('./caps')

const nonce = b4a.alloc(sodium.crypto_stream_NONCEBYTES)

module.exports = class DefaultEncryption {
  static PADDING = 8

  constructor(encryptionKey, hypercoreKey, opts = {}) {
    this.key = encryptionKey
    this.compat = opts.compat === true

    const keys = DefaultEncryption.deriveKeys(encryptionKey, hypercoreKey, opts)

    this.blockKey = keys.block
    this.blindingKey = keys.blinding
  }

  static deriveKeys(encryptionKey, hypercoreKey, { block = false, compat = false } = {}) {
    const subKeys = b4a.alloc(2 * sodium.crypto_stream_KEYBYTES)

    const blockKey = block ? encryptionKey : subKeys.subarray(0, sodium.crypto_stream_KEYBYTES)
    const blindingKey = subKeys.subarray(sodium.crypto_stream_KEYBYTES)

    if (!block) {
      if (compat) {
        // Legacy mode used hypercoreKey as keyed-hash key, which only supports
        // 32-byte keys in sodium. For variable-size crypto keys, derive a
        // stable 32-byte key first to preserve compat behavior shape.
        if (hypercoreKey.byteLength === sodium.crypto_generichash_KEYBYTES) {
          sodium.crypto_generichash_batch(blockKey, [encryptionKey], hypercoreKey)
        } else {
          const compatKey = b4a.allocUnsafe(sodium.crypto_generichash_KEYBYTES)
          sodium.crypto_generichash(compatKey, hypercoreKey)
          sodium.crypto_generichash_batch(blockKey, [encryptionKey], compatKey)
          compatKey.fill(0)
        }
      } else {
        sodium.crypto_generichash_batch(blockKey, [DEFAULT_ENCRYPTION, hypercoreKey, encryptionKey])
      }
    }

    sodium.crypto_generichash(blindingKey, blockKey)

    return {
      blinding: blindingKey,
      block: blockKey
    }
  }

  static blockEncryptionKey(hypercoreKey, encryptionKey) {
    const blockKey = b4a.alloc(sodium.crypto_stream_KEYBYTES)
    sodium.crypto_generichash_batch(blockKey, [DEFAULT_ENCRYPTION, hypercoreKey, encryptionKey])
    return blockKey
  }

  static encrypt(index, block, fork, blockKey, blindingKey) {
    const padding = block.subarray(0, DefaultEncryption.PADDING)
    block = block.subarray(DefaultEncryption.PADDING)

    c.uint64.encode({ start: 0, end: 8, buffer: padding }, fork)
    c.uint64.encode({ start: 0, end: 8, buffer: nonce }, index)

    // Zero out any previous padding.
    nonce.fill(0, 8, 8 + padding.byteLength)

    // Blind the fork ID, possibly risking reusing the nonce on a reorg of the
    // Hypercore. This is fine as the blinding is best-effort and the latest
    // fork ID shared on replication anyway.
    sodium.crypto_stream_xor(padding, padding, nonce, blindingKey)

    nonce.set(padding, 8)

    // The combination of a (blinded) fork ID and a block index is unique for a
    // given Hypercore and is therefore a valid nonce for encrypting the block.
    sodium.crypto_stream_xor(block, block, nonce, blockKey)
  }

  static decrypt(index, block, blockKey) {
    const padding = block.subarray(0, DefaultEncryption.PADDING)
    block = block.subarray(DefaultEncryption.PADDING)

    c.uint64.encode({ start: 0, end: 8, buffer: nonce }, index)

    nonce.set(padding, 8)

    // Decrypt the block using the blinded fork ID.
    sodium.crypto_stream_xor(block, block, nonce, blockKey)
  }

  encrypt(index, block, fork, core) {
    if (core.compat !== this.compat) this._reload(core)
    return DefaultEncryption.encrypt(index, block, fork, this.blockKey, this.blindingKey)
  }

  decrypt(index, block, core) {
    if (core.compat !== this.compat) this._reload(core)
    return DefaultEncryption.decrypt(index, block, this.blockKey)
  }

  padding() {
    return DefaultEncryption.PADDING
  }

  _reload(core) {
    const block = b4a.equals(this.key, this.blockKey)
    const keys = DefaultEncryption.deriveKeys(this.key, core.key, { block, compat: core.compat })

    this.blockKey = keys.block
    this.blindingKey = keys.blinding
  }
}
