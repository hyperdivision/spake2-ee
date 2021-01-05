const h = require('./header')
const { crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE } = require('sodium-native')
const spake = require('./')

const [ OPS, MEM ] = [ crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE ]

const pwd = Buffer.from('password')
const clientId = Buffer.from('client')
const serverId = Buffer.from('server')

const server = new h.SpakeServerState(Buffer.alloc(h.SpakeServerState.byteLength))
const client = new h.SpakeClientState(Buffer.alloc(h.SpakeClientState.byteLength))
const sharedKeys = new h.SpakeSharedKeys(Buffer.alloc(h.SpakeSharedKeys.byteLength))

const store = Buffer.alloc(h.crypto_spake_STOREDBYTES)
const public = Buffer.alloc(h.crypto_spake_PUBLICDATABYTES)

const response1 = Buffer.alloc(h.crypto_spake_RESPONSE1BYTES)
const response2 = Buffer.alloc(h.crypto_spake_RESPONSE2BYTES)
const response3 = Buffer.alloc(h.crypto_spake_RESPONSE3BYTES)

spake.serverStore(store, pwd, OPS, MEM, Buffer.from('579daa4d7bf3ca0e0b6c48b90c4ec515', 'hex'))

spake.step0(server, public, store)
spake.step1(client, response1, public, pwd, Buffer.from('65938d85b4b9649ecb9df6b9176d692dea309d557bca39507750a6883744c60f', 'hex'))
spake.step2(server, response2, clientId, serverId, store, response1, Buffer.from('78a21685c809888742ca71d7a9ea10f2d123564b5661a5e14e18c7ed62e1ce3c', 'hex'))
spake.step3(client, response3, sharedKeys, clientId, serverId, response2)
spake.step4(server, sharedKeys, response3)
