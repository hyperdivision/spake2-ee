const sodium = require('sodium-native')
const assert = require('nanoassert')
const C = require('./lib')
const Reader = require('./lib/reader')

const { createKeys, sharedKeysAndValidators } = C

module.exports = class Client {
  constructor (clientId) {
    this.id = clientId
    this.state = new ClientState()
    this.sharedKeys = new C.SpakeSharedKeys(C.SpakeSharedKeys.byteLength)
  }

  generate (publicData, passwd) {
    const res = new Uint8Array(C.crypto_spake_RESPONSE1BYTES)
    assert(publicData.byteLength === C.crypto_spake_PUBLICDATABYTES)

    this._sanitize()

    const pub = new Reader(publicData)

    const version = pub.u16LE()
    assert(version === C.SERVER_VERSION) // TODO

    const alg = pub.u16LE()
    const opslimit = pub.u64LE()
    const memlimit = pub.u64LE()
    const salt = pub.read(sodium.crypto_pwhash_SALTBYTES)

    const keys = new C.SpakeKeys()
    createKeys(keys, salt, passwd, opslimit, memlimit, alg)

    const x = new Uint8Array(32)
    const gx = new Uint8Array(32)
    const X = res.subarray(0, 32)
    sodium.crypto_core_ed25519_scalar_random(x)
    sodium.crypto_scalarmult_ed25519_base_noclamp(gx, x)
    sodium.crypto_core_ed25519_add(X, gx, keys.M)

    this.state.x = x
    this.state.X = X
    this.state.N = keys.N
    this.state.hK = keys.hK
    this.state.hL = keys.hL

    return res
  }

  finalise (sharedKeys, serverId, msg) {
    assert(sharedKeys instanceof C.SpakeSharedKeys)

    const res = new Uint8Array(C.crypto_spake_RESPONSE3BYTES)
    const validators = new C.SpakeValidators()
    const V = new Uint8Array(32)
    const Z = new Uint8Array(32)
    const gy = new Uint8Array(32)
    const Y = msg.subarray(0, 32)
    const clientValidator = msg.subarray(32)

    sodium.crypto_core_ed25519_sub(gy, Y, this.state.N)
    try {
      sodium.crypto_scalarmult_ed25519_noclamp(Z, this.state.x, gy)
      sodium.crypto_scalarmult_ed25519(V, this.state.hL, gy)
      sharedKeysAndValidators(this.sharedKeys, validators, this.id, serverId, this.state.X, Y, Z, this.state.hK, V)
      sodium.sodium_memcmp(clientValidator, validators.clientValidator)
    } catch {
      this._sanitize()
      throw new Error('Server keys invalid: protocol aborted.')
    }
    res.set(validators.serverValidator.subarray(0, 32))
    validators._sanitize()

    sharedKeys.clientSk.set(this.sharedKeys.clientSk)
    sharedKeys.serverSk.set(this.sharedKeys.serverSk)
    this._sanitize()

    return res
  }

  _sanitize () {
    this.state._sanitize()
    this.sharedKeys._sanitize()
  }
}

class ClientState {
  constructor () {
    this.x = new Uint8Array(32)
    this.X = new Uint8Array(32)
    this.N = new Uint8Array(32)
    this.hK = new Uint8Array(32)
    this.hL = new Uint8Array(32)
  }

  _sanitize () {
    this.x.fill(0)
    this.X.fill(0)
    this.N.fill(0)
    this.hK.fill(0)
    this.hL.fill(0)
  }
}
