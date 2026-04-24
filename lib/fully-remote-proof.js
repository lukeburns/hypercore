// this helper is for fully remote proofs, is like in a push notification where no other context exists

const { MerkleTree } = require('./merkle-tree.js')
const messages = require('./messages.js')
const b4a = require('b4a')
const c = require('compact-encoding')
const crypto = require('hypercore-crypto')
const flat = require('flat-tree')
const multisig = require('./multisig')
const cryptoSpec = require('./crypto-spec')

class SlimSession {
  constructor(storage, auth, head, roots) {
    this.fork = head ? head.fork : 0
    this.roots = roots
    this.length = head ? head.length : 0
    this.signature = head ? head.signature : null
    this.ancestors = this.length
    this.byteLength = 0
    this.prologue = auth.manifest.prologue
    this.storage = storage

    for (let i = 0; i < roots.length; i++) this.byteLength += roots[i].size
  }
}

module.exports = { verify, proof }

async function verify(storage, buffer, { referrer = null } = {}) {
  const state = { buffer, start: 0, end: buffer.byteLength }

  const discoveryKey = fixedBuffer(cryptoSpec.HASH_BYTES).decode(state)
  const proof = messages.wire.data.decode(state)

  const result = {
    key: null,
    discoveryKey,
    newer: true,
    length: 0,
    proof,
    block: null
  }

  const core = await storage.resumeCore(discoveryKey)
  if (core === null) return null

  let rx = core.read()
  const authPromise = rx.getAuth()
  const headPromise = rx.getHead()
  const referrerPromise = rx.getUserData('referrer')

  rx.tryFlush()

  const [auth, head, ref] = await Promise.all([authPromise, headPromise, referrerPromise])

  if (auth === null) return null

  if (referrer && (!ref || !b4a.equals(ref, referrer))) return null

  rx = core.read()

  const rootPromises = []

  for (const index of flat.fullRoots(head ? 2 * head.length : 0)) {
    rootPromises.push(rx.getTreeNode(index))
  }

  rx.tryFlush()

  let roots = await Promise.all(rootPromises)
  if (roots.some(isNull)) roots = []

  const length = head ? head.length : 0

  if (!auth.manifest || !auth.manifest.signers.length) return null

  const batch = await MerkleTree.verifyFullyRemote(new SlimSession(core, auth, head, roots), proof)
  const publicKey = auth.manifest.signers[0].publicKey

  let signable = null
  let signature = null

  if (auth.manifest.version === 0) {
    signable = batch.signable(auth.manifest.signers[0].namespace)
    signature = batch.signature
  } else {
    let decoded = null

    try {
      decoded = multisig.inflate(batch.signature)
    } catch {
      return null
    }

    if (!decoded.proofs.length) return null
    if (decoded.proofs[0].signer !== 0) return null

    signable = batch.signable(auth.key)
    signature = decoded.proofs[0].signature
  }

  if (!crypto.verify(signable, signature, publicKey)) {
    return null
  }

  result.key = auth.key
  result.discoveryKey = discoveryKey
  result.newer = batch.length > length
  result.length = batch.length
  result.block = proof.block

  return result
}

async function proof(sender, { index, block = null, upgrade = null } = {}) {
  const proof = await sender.proof({
    block: block ? { index, nodes: 0 } : null,
    upgrade: upgrade ? upgrade : { start: 0, length: sender.length }
  })

  if (block) proof.block.value = block
  proof.manifest = sender.core.header.manifest

  const state = { buffer: null, start: 0, end: 0 }
  const data = { request: 0, ...proof }

  const discoveryKeyEncoding = fixedBuffer(cryptoSpec.HASH_BYTES)

  discoveryKeyEncoding.preencode(state, sender.discoveryKey)
  messages.wire.data.preencode(state, data)

  state.buffer = b4a.allocUnsafe(state.end)

  discoveryKeyEncoding.encode(state, sender.discoveryKey)
  messages.wire.data.encode(state, data)

  return state.buffer
}

function isNull(x) {
  return x === null
}

function fixedBuffer(length) {
  return {
    preencode(state, buffer) {
      if (buffer.byteLength !== length) throw new Error('Invalid fixed buffer length')
      state.end += length
    },
    encode(state, buffer) {
      if (buffer.byteLength !== length) throw new Error('Invalid fixed buffer length')
      state.buffer.set(buffer, state.start)
      state.start += length
    },
    decode(state) {
      const end = state.start + length
      if (end > state.end) throw new Error('Invalid fixed buffer length')
      const buffer = state.buffer.subarray(state.start, end)
      state.start = end
      return buffer
    }
  }
}
