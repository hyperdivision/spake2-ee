const sodium = require('sodium-native')
const assert = require('nanoassert')
const C = require('./header')
const Writer = require('./writer')
const Reader = require('./reader')
const SERVER_VERSION = 0x01

function createKeys (keys, salt, passwd, opslimit, memlimit, alg) {
  const hMNKL = Buffer.alloc(32 * 4)
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

function serverStore (storedData, passwd, opslimit, memlimit) {
  const keys = new C.SpakeKeys(Buffer.alloc(C.SpakeKeys.byteLength))

  const salt = Buffer.alloc(sodium.crypto_pwhash_SALTBYTES)
  sodium.randombytes_buf(salt)

  createKeys(keys, salt, passwd, opslimit, memlimit)

  const w = new Writer(storedData)

  w.u16LE(SERVER_VERSION)
    .u16LE(sodium.crypto_pwhash_ALG_DEFAULT)
    .doubleLE(opslimit)
    .doubleLE(memlimit)
    .write(salt)
    .write(keys.M)
    .write(keys.N)
    .write(keys.hK)
    .write(keys.L)
}

function sharedKeysAndValidators (sharedKeys, validators, clientId, serverId, X, Y, Z, hK, V) {
    const hst = sodium.crypto_generichash_state()
    const k0 = new Uint8Array(sodium.crypto_kdf_KEYBYTES)
    let len = Buffer.alloc(1)
    let hVersion

    assert ((clientId.byteLength | serverId.byteLength) <= 0xff)
    crypto_generichash_init(hst, null, k0.byteLength)

    hVersion = H_VERSION
    crypto_generichash_update(hst, hVersion, 1)

    len[0] = clientId.byteLength
    crypto_generichash_update(hst, len)
    crypto_generichash_update(hst, clientId)

    len[0] = serverId.byteLength
    crypto_generichash_update(hst, len)
    crypto_generichash_update(hst, serverId)

    crypto_generichash_update(hst, X)
    crypto_generichash_update(hst, Y)
    crypto_generichash_update(hst, Z)
    crypto_generichash_update(hst, hK)
    crypto_generichash_update(hst, V)

    crypto_generichash_final(hst, k0)

    sodium.crypto_kdf_derive_from_key(sharedKeys.client_sk, 0, Buffer.from('PAKE2+EE'), k0)
    sodium.crypto_kdf_derive_from_key(sharedKeys.server_sk, 1, Buffer.from('PAKE2+EE'), k0)
    sodium.crypto_kdf_derive_from_key(validators.client_validator, 2, Buffer.from('PAKE2+EE'), k0)
    sodium.crypto_kdf_derive_from_key(validators.server_validator, 3, Buffer.from('PAKE2+EE'), k0)

    k0.fill(0)

    return 0
}


function validatePublicData (publicData, expectedAlg, expectedOpslimit, expectedMemlimit) {
  assert(publicData.byteLength === C.crypto_spake_PUBLICDATABYTES)

  const reader = new Reader(publicData)
  reader.u16LE()

  const alg = reader.u16LE()
  const opslimit = reader.doubleLE()
  const memlimit = reader.doubleLE()

  return alg === expectedAlg &&
    opslimit === expectedOpslimit &&
    memlimit === expectedMemlimit
}

function step0 (serverState, publicData, storedData) {
  assert(serverState instanceof C.SpakeServerState)
  assert(publicData.byteLength === C.crypto_spake_PUBLICDATABYTES)
  assert(storedData.byteLength === C.crypto_spake_STOREDBYTES)

  serverState.buf.fill(0)

  const stored = new Reader(storedData)
  const public = new Writer(publicData)

  const version = stored.u16LE()
  assert(version === SERVER_VERSION) // TODO

  public.u16LE(version)
  public.u16LE(stored.u16LE()) // alg
  public.doubleLE(stored.doubleLE()) // opslimit
  public.doubleLE(stored.doubleLE()) // memlimit
  public.write(stored.read(sodium.crypto_pwhash_SALTBYTES)) // salt
}

function step1 (clientState, response1, publicData, passwd) {
  assert(clientState instanceof C.SpakeClientState)
  assert(response1.byteLength === C.crypto_spake_RESPONSE1BYTES)
  assert(publicData.byteLength === C.crypto_spake_PUBLICDATABYTES)

  clientState.buf.fill(0)

  const public = new Reader(publicData)

  const version = public.u16LE()
  assert(version === SERVER_VERSION) // TODO

  const alg = public.u16LE()
  const opslimit = public.doubleLE()
  const memlimit = public.doubleLE()
  const salt = public.read(sodium.crypto_pwhash_SALTBYTES)

  const keys = createKeys(C.SpakeKeys(Buffer.alloc(SpakeKeys.byteLength)), salt, passwd, opslimit, memlimit, alg)
  const x = Buffer.alloc(32)
  const gx = Buffer.alloc(32)
  const X = response1.subarray(0, 32)
  sodium.crypto_core_ed25519_scalar_random(x)
  sodium.crypto_scalarmult_ed25519_base_noclamp(gx, x)
  sodium.crypto_core_ed25519_add(X, gx, keys.M)
  clientState.hK.set(keys.hK)
  clientState.hL.set(keys.hL)
  clientState.N.set(keys.N)
  clientState.x.set(x)
  clientState.X.set(X)

  sodium.sodium_memzero(keys.buf)
}

function step2 (serverState, response2, clientId, serverId, storedData, response1) {
  const validators = new C.SpakeValidators()
  const keys = new C.SpakeKeys(Buffer.alloc(C.SpakeKeys.byteLength))
  const V = new Uint8Array(32)
  const Z = new Uint8Array(32)
  const gx = new Uint8Array(32)
  const gy = new Uint8Array(32)
  const y = new Uint8Array(32)

  const data = new Reader(storedData)

  const Y = response2.subarray(0, 32)
  const clientValidator = response2.subarray(32)
  const X = response1

  let i = 0
  let v16
  let v64

  v16 = data.u16LE() /* version */
  assert(v16 === SER_VERSION)

  v16 = data.u16LE() /* alg */
  v64 = data.doubleLE() /* opslimit */
  v64 = data.doubleLE() /* memlimit */
  const salt = data.read(sodium.crypto_pwhash_SALTBYTES) /* salt */
  keys.M = data.read(32)
  keys.N = data.read(32)
  keys.hK = data.read(32)
  keys.L = data.read(32)

  sodium.crypto_core_ed25519_scalar_random(y)
  sodium.crypto_scalarmult_ed25519_base_noclamp(gy, y)
  sodium.crypto_core_ed25519_add(Y, gy, keys.N)

  sodium.crypto_core_ed25519_sub(gx, X, keys.M)
  try {
    sodium.crypto_scalarmult_ed25519_noclamp(Z, y, gx)
    sodium.crypto_scalarmult_ed25519_noclamp(V, y, keys.L)
    sharedKeysAndValidators(serverState.sharedKeys, validators, clientId, serverId, X, Y, Z, keys.hK, V)
  } catch {
    serverState.buf.fill(0)
    throw new Error('Client keys invalid: protocol aborted.')
  }

  clientValidator.set(validators.clientValidator.subarray(0, 32))
  serverState.serverValidator.set(validators.serverValidator.subarray(0, 32))
}

function step3 (clientState, response3, sharedKeys, clientId, serverId, response2) {
  const validators = new C.SpakeValidators
  const V = new Uint8Array(32)
  const Z = new Uint8Array(32)
  const gy = new Uint8Array(32)
  const serverValidator = response3
  const Y = response2.subarray(0, 32)
  const clientValidator = response2.subarray(32)

  sodium.crypto_core_ed25519_sub(gy, Y, clientState.N)
  try {
    sodium.crypto_scalarmult_ed25519_noclamp(Z, clientState.x, gy)
    sodium.crypto_scalarmult_ed25519(V, clientState.h_L, gy)
    sharedKeysAndValidators(sharedKeys, validators, clientId, serverId, clientState.X, Y, Z, clientState.hK, V)
    sodium.sodium_memcmp(clientValidator, validators.clientValidator, 32)
  } catch {
    clientState.buf.fill(0)
    throw new Error('Server keys invalid: protocol aborted.')
  }
  serverValidator.set(validators.serverValidator.subarray(0, 32))
  clientState.buf.fill(0)
}

function step4 (serverState, sharedKeys, response3) {
  const serverValidator = response3

  if (sodium.sodium_memcmp(serverValidator, serverState.serverValidator, 32) != 0) {
    serverState.buf.fill(0)
    throw new Error('Client response invalid: aborting protocol')
  }

  sharedKeys.set(serverState.sharedKeys)
  serverState.buf.fill(0)
}
