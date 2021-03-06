const uint64be = require('uint64be')
const flat = require('flat-tree')
const createCache = require('./cache')

module.exports = Storage

const noarr = []

function Storage (create, opts) {
  if (!(this instanceof Storage)) return new Storage(create, opts)

  const cache = createCache(opts)

  this.treeCache = cache.tree || null
  this.dataCache = cache.data || null
  this.key = null
  this.secretKey = null
  this.tree = null
  this.data = null
  this.bitfield = null
  this.signatures = null
  this.create = create

  if (!opts) opts = {}
  const crypto = opts.crypto || {}

  this.publicKeySize = crypto.publicKeySize || 32
  this.secretKeySize = crypto.secretKeySize || 64
  this.signatureSize = crypto.signatureSize || 64
  this.signatureType = crypto.signatureType || 'Ed25519'
}

Storage.prototype.putData = function (index, data, nodes, cb) {
  if (!cb) cb = noop
  const self = this
  if (!data.length) return cb(null)
  this.dataOffset(index, nodes, function (err, offset, size) {
    if (err) return cb(err)
    if (size !== data.length) return cb(new Error('Unexpected data size'))
    self.data.write(offset, data, cb)
  })
}

Storage.prototype.getData = function (index, cb) {
  const self = this
  const cached = this.dataCache && this.dataCache.get(index)
  if (cached) return process.nextTick(cb, null, cached)
  this.dataOffset(index, noarr, function (err, offset, size) {
    if (err) return cb(err)
    self.data.read(offset, size, (err, data) => {
      if (err) return cb(err)
      if (self.dataCache) self.dataCache.set(index, data)
      return cb(null, data)
    })
  })
}

Storage.prototype.nextSignature = function (index, cb) {
  const self = this

  this._getSignature(index, function (err, signature) {
    if (err) return cb(err)
    if (isBlank(signature)) return self.nextSignature(index + 1, cb)
    cb(null, { index: index, signature: signature })
  })
}

Storage.prototype.getSignature = function (index, cb) {
  this._getSignature(index, function (err, signature) {
    if (err) return cb(err)
    if (isBlank(signature)) return cb(new Error('No signature found'))
    cb(null, signature)
  })
}

// Caching not enabled for signatures because they are rarely reused.
Storage.prototype._getSignature = function (index, cb) {
  this.signatures.read(32 + this.signatureSize * index, 64, cb)
}

Storage.prototype.putSignature = function (index, signature, cb) {
  this.signatures.write(32 + this.signatureSize * index, signature, cb)
}

Storage.prototype.deleteSignatures = function (start, end, cb) {
  this.signatures.del(32 + 64 * start, (end - start) * 64, cb)
}

Storage.prototype.dataOffset = function (index, cachedNodes, cb) {
  const roots = flat.fullRoots(2 * index)
  const self = this
  let offset = 0
  let pending = roots.length
  let error = null
  const blk = 2 * index

  if (!pending) {
    pending = 1
    onnode(null, null)
    return
  }

  for (let i = 0; i < roots.length; i++) {
    const node = findNode(cachedNodes, roots[i])
    if (node) onnode(null, node)
    else this.getNode(roots[i], onnode)
  }

  function onlast (err, node) {
    if (err) return cb(err)
    cb(null, offset, node.size)
  }

  function onnode (err, node) {
    if (err) error = err
    if (node) offset += node.size
    if (--pending) return

    if (error) return cb(error)

    const last = findNode(cachedNodes, blk)
    if (last) onlast(null, last)
    else self.getNode(blk, onlast)
  }
}

// Caching not enabled for batch reads because they'd be complicated to batch and they're rarely used.
Storage.prototype.getDataBatch = function (start, n, cb) {
  const result = new Array(n)
  const sizes = new Array(n)
  const self = this

  this.dataOffset(start, noarr, function (err, offset, size) {
    if (err) return cb(err)

    start++
    n--

    if (n <= 0) return ontree(null, null)
    self.tree.read(32 + 80 * start, 80 * n - 40, ontree)

    function ontree (err, buf) {
      if (err) return cb(err)

      let total = sizes[0] = size

      if (buf) {
        for (let i = 1; i < sizes.length; i++) {
          sizes[i] = uint64be.decode(buf, 32 + (i - 1) * 80)
          total += sizes[i]
        }
      }

      self.data.read(offset, total, ondata)
    }

    function ondata (err, buf) {
      if (err) return cb(err)
      let total = 0
      for (let i = 0; i < result.length; i++) {
        result[i] = buf.slice(total, total += sizes[i])
      }

      cb(null, result)
    }
  })
}

Storage.prototype.getNode = function (index, cb) {
  if (this.treeCache) {
    const cached = this.treeCache.get(index)
    if (cached) return cb(null, cached)
  }

  const self = this

  this.tree.read(32 + 40 * index, 40, function (err, buf) {
    if (err) return cb(err)

    const hash = buf.slice(0, 32)
    const size = uint64be.decode(buf, 32)

    if (!size && isBlank(hash)) return cb(new Error('No node found'))

    const val = new Node(index, hash, size, null)
    if (self.treeCache) self.treeCache.set(index, val)
    cb(null, val)
  })
}

Storage.prototype.putNodeBatch = function (index, nodes, cb) {
  if (!cb) cb = noop

  const buf = Buffer.alloc(nodes.length * 40)

  for (let i = 0; i < nodes.length; i++) {
    const offset = i * 40
    const node = nodes[i]
    if (!node) continue
    node.hash.copy(buf, offset)
    uint64be.encode(node.size, buf, 32 + offset)
  }

  this.tree.write(32 + 40 * index, buf, cb)
}

Storage.prototype.putNode = function (index, node, cb) {
  if (!cb) cb = noop

  // TODO: re-enable put cache. currently this causes a memleak
  // because node.hash is a slice of the big data buffer on replicate
  // if (this.cache) this.cache.set(index, node)

  const buf = Buffer.allocUnsafe(40)

  node.hash.copy(buf, 0)
  uint64be.encode(node.size, buf, 32)
  this.tree.write(32 + 40 * index, buf, cb)
}

Storage.prototype.putBitfield = function (offset, data, cb) {
  this.bitfield.write(32 + offset, data, cb)
}

Storage.prototype.close = function (cb) {
  if (!cb) cb = noop
  let missing = 6
  let error = null

  close(this.bitfield, done)
  close(this.tree, done)
  close(this.data, done)
  close(this.key, done)
  close(this.secretKey, done)
  close(this.signatures, done)

  function done (err) {
    if (err) error = err
    if (--missing) return
    cb(error)
  }
}

Storage.prototype.destroy = function (cb) {
  if (!cb) cb = noop
  let missing = 6
  let error = null

  destroy(this.bitfield, done)
  destroy(this.tree, done)
  destroy(this.data, done)
  destroy(this.key, done)
  destroy(this.secretKey, done)
  destroy(this.signatures, done)

  function done (err) {
    if (err) error = err
    if (--missing) return
    cb(error)
  }
}

Storage.prototype.openKey = function (opts, cb) {
  if (typeof opts === 'function') return this.openKey({}, opts)
  if (!this.key) this.key = this.create('key', opts)
  this.key.read(0, this.publicKeySize, cb)
}

Storage.prototype.open = function (opts, cb) {
  if (typeof opts === 'function') return this.open({}, opts)

  const self = this
  let error = null
  let missing = 5

  if (!this.key) this.key = this.create('key', opts)
  if (!this.secretKey) this.secretKey = this.create('secret_key', opts)
  if (!this.tree) this.tree = this.create('tree', opts)
  if (!this.data) this.data = this.create('data', opts)
  if (!this.bitfield) this.bitfield = this.create('bitfield', opts)
  if (!this.signatures) this.signatures = this.create('signatures', opts)

  const result = {
    bitfield: [],
    bitfieldPageSize: 3584, // we upgraded the page size to fix a bug
    secretKey: null,
    key: null
  }

  this.bitfield.read(0, 32, function (err, h) {
    if (err && err.code === 'ELOCKED') return cb(err)
    if (h) result.bitfieldPageSize = h.readUInt16BE(5)
    self.bitfield.write(0, header(0, result.bitfieldPageSize, null), function (err) {
      if (err) return cb(err)
      readAll(self.bitfield, 32, result.bitfieldPageSize, function (err, pages) {
        if (pages) result.bitfield = pages
        done(err)
      })
    })
  })

  this.signatures.write(0, header(1, this.signatureSize, this.signatureType), done)
  this.tree.write(0, header(2, 40, 'BLAKE2b'), done)

  // TODO: Improve the error handling here.
  this.secretKey.read(0, this.secretKeySize, function (_, data) {
    if (data) result.secretKey = data
    done(null)
  })

  this.key.read(0, this.publicKeySize, function (_, data) {
    if (data) result.key = data
    done(null)
  })

  function done (err) {
    if (err) error = err
    if (--missing) return
    if (error) cb(error)
    else cb(null, result)
  }
}

Storage.Node = Node

function noop () {}

function header (type, size, name) {
  const buf = Buffer.alloc(32)

  // magic number
  buf[0] = 5
  buf[1] = 2
  buf[2] = 87
  buf[3] = type

  // version
  buf[4] = 0

  // block size
  buf.writeUInt16BE(size, 5)

  if (name) {
    // algo name
    buf[7] = name.length
    buf.write(name, 8)
  }

  return buf
}

function Node (index, hash, size) {
  this.index = index
  this.hash = hash
  this.size = size
}

function findNode (nodes, index) {
  for (let i = 0; i < nodes.length; i++) {
    if (nodes[i].index === index) return nodes[i]
  }
  return null
}

function isBlank (buf) {
  for (let i = 0; i < buf.length; i++) {
    if (buf[i]) return false
  }
  return true
}

function close (st, cb) {
  if (st.close) st.close(cb)
  else cb()
}

function destroy (st, cb) {
  if (st.destroy) st.destroy(cb)
  else cb()
}

function statAndReadAll (st, offset, pageSize, cb) {
  st.stat(function (err, stat) {
    if (err) return cb(null, [])

    const result = []

    loop(null, null)

    function loop (err, batch) {
      if (err) return cb(err)

      if (batch) {
        offset += batch.length
        for (let i = 0; i < batch.length; i += pageSize) {
          result.push(batch.slice(i, i + pageSize))
        }
      }

      const next = Math.min(stat.size - offset, 32 * pageSize)
      if (!next) return cb(null, result)

      st.read(offset, next, loop)
    }
  })
}

function readAll (st, offset, pageSize, cb) {
  if (st.statable === true) return statAndReadAll(st, offset, pageSize, cb)

  const bufs = []

  st.read(offset, pageSize, loop)

  function loop (err, buf) {
    if (err) return cb(null, bufs)
    bufs.push(buf)
    st.read(offset + bufs.length * pageSize, pageSize, loop)
  }
}
