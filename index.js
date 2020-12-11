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

function step2 (serverState, response2, clientId, serverId, storedData, response1) {}

function step3 (clientState, response3, sharedKeys, clientId, serverId, response2) {}

function step4 (serverState, sharedKeys, response3) {}
