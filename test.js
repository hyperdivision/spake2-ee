const { crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE } = require('sodium-native')
const { ServerSide, ClientSide, SpakeSharedKeys } = require('./')

const [ OPS, MEM ] = [ crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE ]

const pwd = Buffer.from('password')
const clientId = Buffer.from('client')
const serverId = Buffer.from('server')

const storedData =  ClientSide.register(pwd, OPS, MEM, Buffer.from('579daa4d7bf3ca0e0b6c48b90c4ec515', 'hex'))

const server = new ServerSide(serverId, storedData)
const client = new ClientSide(clientId)
const sharedKeys = new SpakeSharedKeys()

const public = server.init()

const res1 = client.generate(public, pwd, Buffer.from('65938d85b4b9649ecb9df6b9176d692dea309d557bca39507750a6883744c60f', 'hex'))
const res2 = server.respond(client.id, res1, Buffer.from('78a21685c809888742ca71d7a9ea10f2d123564b5661a5e14e18c7ed62e1ce3c', 'hex'))
const res3 = client.finalise(sharedKeys, server.id, res2)
const sharedKeys1 = server.finalise(res3)

console.log(Buffer.compare(sharedKeys1.clientSk, sharedKeys.clientSk) === 0)
console.log(Buffer.compare(sharedKeys1.serverSk, sharedKeys.serverSk) === 0)
