const sodium = require('sodium-native')
const assert = require('nanoassert')
const Reader = require('./reader')

const H_VERSION = 0x01
const SERVER_VERSION = 0x01

const crypto_spake_DUMMYKEYBYTES = 32
const crypto_spake_PUBLICDATABYTES = 36
const crypto_spake_RESPONSE1BYTES = 32
const crypto_spake_RESPONSE2BYTES = 64
const crypto_spake_RESPONSE3BYTES = 32
const crypto_spake_SHAREDKEYBYTES = 32
const crypto_spake_STOREDBYTES = 164

module.exports = {
  crypto_spake_DUMMYKEYBYTES,
  crypto_spake_PUBLICDATABYTES,
  crypto_spake_RESPONSE1BYTES,
  crypto_spake_RESPONSE2BYTES,
  crypto_spake_RESPONSE3BYTES,
  crypto_spake_SHAREDKEYBYTES,
  crypto_spake_STOREDBYTES,
  SERVER_VERSION,
  createKeys,
  sharedKeysAndValidators,
  validatePublicData
}

module.exports.SpakeSharedKeys = class SpakeSharedKeys {
  constructor () {
    this.clientSk = new Uint8Array(crypto_spake_SHAREDKEYBYTES)
    this.serverSk = new Uint8Array(crypto_spake_SHAREDKEYBYTES)
  }

  _sanitize () {
    this.clientSk.fill(0)
    this.serverSk.fill(0)
  }
}

module.exports.SpakeKeys = class SpakeKeys {
  constructor () {
    this.L = new Uint8Array(32)
    this.M = new Uint8Array(32)
    this.N = new Uint8Array(32)
    this.hK = new Uint8Array(32)
    this.hL = new Uint8Array(32)
  }

  _sanitize () {
    this.L.fill(0)
    this.M.fill(0)
    this.N.fill(0)
    this.hK.fill(0)
    this.hL.fill(0)
  }
}

module.exports.SpakeValidators = class SpakeValidators {
  constructor () {
    this.clientValidator = new Uint8Array(32)
    this.serverValidator = new Uint8Array(32)
  }

  _sanitize () {
    this.clientValidator.fill()
    this.serverValidator.fill()
  }
}

function createKeys (keys, salt, passwd, opslimit, memlimit, alg) {
  const hMNKL = new Uint8Array(32 * 4)
  const hM = hMNKL.subarray(32 * 0, 32 * 1)
  const hN = hMNKL.subarray(32 * 1, 32 * 2)
  const hK = hMNKL.subarray(32 * 2, 32 * 3)
  const hL = hMNKL.subarray(32 * 3, 32 * 4)

  sodium.crypto_pwhash(hMNKL, passwd, salt, opslimit, memlimit, alg)

  sodium.crypto_core_ed25519_from_uniform(keys.M, hM)
  sodium.crypto_core_ed25519_from_uniform(keys.N, hN)
  keys.hK.set(hK)
  keys.hL.set(hL)
  sodium.crypto_scalarmult_ed25519_base(keys.L, keys.hL)
}

function sharedKeysAndValidators (sharedKeys, validators, clientId, serverId, X, Y, Z, hK, V) {
  const hst = new Uint8Array(sodium.crypto_generichash_STATEBYTES)
  const k0 = new Uint8Array(sodium.crypto_kdf_KEYBYTES)
  const len = new Uint8Array(1)
  const hVersion = new Uint8Array([H_VERSION])

  assert((clientId.byteLength | serverId.byteLength) <= 0xff)
  sodium.crypto_generichash_init(hst, null, k0.byteLength)

  sodium.crypto_generichash_update(hst, hVersion)

  len[0] = clientId.byteLength
  sodium.crypto_generichash_update(hst, len)
  sodium.crypto_generichash_update(hst, clientId)

  len[0] = serverId.byteLength
  sodium.crypto_generichash_update(hst, len)
  sodium.crypto_generichash_update(hst, serverId)

  sodium.crypto_generichash_update(hst, X)
  sodium.crypto_generichash_update(hst, Y)
  sodium.crypto_generichash_update(hst, Z)
  sodium.crypto_generichash_update(hst, hK)
  sodium.crypto_generichash_update(hst, V)

  sodium.crypto_generichash_final(hst, k0)

  sodium.crypto_kdf_derive_from_key(sharedKeys.clientSk, 0, Buffer.from('PAKE2+EE'), k0)
  sodium.crypto_kdf_derive_from_key(sharedKeys.serverSk, 1, Buffer.from('PAKE2+EE'), k0)
  sodium.crypto_kdf_derive_from_key(validators.clientValidator, 2, Buffer.from('PAKE2+EE'), k0)
  sodium.crypto_kdf_derive_from_key(validators.serverValidator, 3, Buffer.from('PAKE2+EE'), k0)

  k0.fill(0)

  return 0
}

function validatePublicData (publicData, expectedAlg, expectedOpslimit, expectedMemlimit) {
  assert(publicData.byteLength === crypto_spake_PUBLICDATABYTES)

  const reader = new Reader(publicData)
  reader.u16LE()

  const alg = reader.u16LE()
  const opslimit = reader.u64LE()
  const memlimit = reader.u64LE()

  return alg === expectedAlg &&
    opslimit === expectedOpslimit &&
    memlimit === expectedMemlimit
}
