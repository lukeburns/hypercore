const Hypercore = require('../')
const Hyperswarm = require('hyperswarm')
const SecretStream = require('@hyperswarm/secret-stream')
const swarmCrypto = require('hyperswarm-crypto')

const core = new Hypercore('./clone', process.argv[2])

start()

async function start() {
  assertBoundPqUpgrade()

  await core.ready()

  const swarm = new Hyperswarm()
  swarm.on('connection', (socket, info) => {
    console.log('connection', info.client, info.server)
    const upgraded = new SecretStream(info.client, socket, {
      upgrade: 'bound-pq'
    })
    core.replicate(upgraded)
  })
  const discovery = swarm.join(core.discoveryKey, { server: false, client: true })
  await discovery.flushed()

  console.log((await core.get(42)).toString())
  console.log((await core.get(142)).toString())
  console.log((await core.get(511)).toString())
  console.log((await core.get(512)).toString())
  console.log((await core.get(513)).toString())
}

function assertBoundPqUpgrade() {
  if (!swarmCrypto.handshakeUpgradeNeedsOuterHash?.({ upgrade: 'bound-pq' })) {
    throw new Error('bound-pq upgrade backend is not installed')
  }
}
