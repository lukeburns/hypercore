const Hypercore = require('../')
const Hyperswarm = require('hyperswarm')
const SecretStream = require('@hyperswarm/secret-stream')
const swarmCrypto = require('hyperswarm-crypto')

const core = new Hypercore('./source')

start()

async function start() {
  assertBoundPqUpgrade()

  await core.ready()
  while (core.length < 1000) {
    await core.append('block #' + core.length)
  }

  const swarm = new Hyperswarm()
  swarm.on('connection', (socket, info) => {
    console.log('connection', info.client, info.server)
    const upgraded = new SecretStream(info.client, socket, {
      upgrade: 'bound-pq'
    })
    core.replicate(upgraded)
  })
  const discovery = swarm.join(core.discoveryKey, { server: true, client: false })
  await discovery.flushed()

  console.log('Core:', core.key.toString('hex'))
}

function assertBoundPqUpgrade() {
  if (!swarmCrypto.handshakeUpgradeNeedsOuterHash?.({ upgrade: 'bound-pq' })) {
    throw new Error('bound-pq upgrade backend is not installed')
  }
}
