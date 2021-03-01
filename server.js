const sodium = require('sodium-native')
const assert = require('nanoassert')
const C = require('./lib')
const Writer = require('./lib/writer')
const Reader = require('./lib/reader')

const { createKeys, sharedKeysAndValidators } = C

module.exports = class ServerSide {
  constructor (serverId, storedData) {
    assert(storedData.byteLength === C.crypto_spake_STOREDBYTES)

    this.id = serverId
    this.validator = new Uint8Array(32)
    this.sharedKeys = new C.SpakeSharedKeys(C.SpakeSharedKeys.byteLength)
    this.storedData = storedData
  }

  init () {
    this._sanitize()

    const publicData = new Uint8Array(C.crypto_spake_PUBLICDATABYTES)

    const stored = new Reader(this.storedData)
    const pub = new Writer(publicData)

    const version = stored.u16LE()
    assert(version === C.SERVER_VERSION) // TODO

    pub.u16LE(version)
    pub.u16LE(stored.u16LE()) // alg
    pub.u64LE(stored.u64LE()) // opslimit
    pub.u64LE(stored.u64LE()) // memlimit
    pub.write(stored.read(sodium.crypto_pwhash_SALTBYTES)) // salt

    return publicData
  }

  respond (clientId, msg) {
    const res = new Uint8Array(C.crypto_spake_RESPONSE2BYTES)
    const validators = new C.SpakeValidators()
    const keys = new C.SpakeKeys()
    const V = new Uint8Array(32)
    const Z = new Uint8Array(32)
    const gx = new Uint8Array(32)
    const gy = new Uint8Array(32)

    const data = new Reader(this.storedData)

    const Y = res.subarray(0, 32)
    const clientValidator = res.subarray(32)
    const X = msg

    const i = 0
    let v16
    let v64

    v16 = data.u16LE() /* version */
    assert(v16 === C.SERVER_VERSION)

    v16 = data.u16LE() /* alg */
    v64 = data.u64LE() /* opslimit */
    v64 = data.u64LE() /* memlimit */
    const salt = data.read(sodium.crypto_pwhash_SALTBYTES) /* salt */
    keys.M = data.read(32)
    keys.N = data.read(32)
    keys.hK = data.read(32)
    keys.L = data.read(32)

    const y = new Uint8Array(32)
    sodium.crypto_core_ed25519_scalar_random(y)
    sodium.crypto_scalarmult_ed25519_base_noclamp(gy, y)
    sodium.crypto_core_ed25519_add(Y, gy, keys.N)

    sodium.crypto_core_ed25519_sub(gx, X, keys.M)
    try {
      sodium.crypto_scalarmult_ed25519_noclamp(Z, y, gx)
      sodium.crypto_scalarmult_ed25519_noclamp(V, y, keys.L)
      sharedKeysAndValidators(this.sharedKeys, validators, clientId, this.id, X, Y, Z, keys.hK, V)
    } catch (e) {
      this._sanitize()
      throw new Error('Client keys invalid: protocol aborted.')
    }

    clientValidator.set(validators.clientValidator)
    this.validator.set(validators.serverValidator)
    validators._sanitize()

    return res
  }

  finalise (msg) {
    const sharedKeys = new C.SpakeSharedKeys()
    const serverValidator = msg

    if (!sodium.sodium_memcmp(serverValidator, this.validator)) {
      this._sanitize()
      throw new Error('Client response invalid: aborting protocol')
    }

    sharedKeys.clientSk.set(this.sharedKeys.clientSk)
    sharedKeys.serverSk.set(this.sharedKeys.serverSk)
    this._sanitize()

    return sharedKeys
  }

  _sanitize () {
    this.validator.fill(0)
    this.sharedKeys._sanitize()
  }
}
