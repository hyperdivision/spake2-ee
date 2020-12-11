const assert = require('nanoassert')

const crypto_spake_DUMMYKEYBYTES = 32
const crypto_spake_PUBLICDATABYTES = 36
const crypto_spake_RESPONSE1BYTES = 32
const crypto_spake_RESPONSE2BYTES = 64
const crypto_spake_RESPONSE3BYTES = 32
const crypto_spake_SHAREDKEYBYTES = 32
const crypto_spake_STOREDBYTES = 164

class SpakeSharedKeys {
  static byteLength = 2 * crypto_spake_SHAREDKEYBYTES

  constructor (buf) {
    assert(buf.byteLength >= SpakeSharedKeys.byteLength)
    this.buf = buf
  }

  get clientSk () { return this.buf.subarray(crypto_spake_SHAREDKEYBYTES * 0, crypto_spake_SHAREDKEYBYTES * 1) }
  get serverSk () { return this.buf.subarray(crypto_spake_SHAREDKEYBYTES * 1, crypto_spake_SHAREDKEYBYTES * 2) }
}

class SpakeClientState {
  static byteLength = 32 * 5

  constructor (buf) {
    assert(buf.byteLength >= SpakeClientState.byteLength)
    this.buf = buf
  }

  get hK () { return this.buf.subarray(32 * 0, 32 * 1) }
  get hL () { return this.buf.subarray(32 * 1, 32 * 2) }
  get N () { return this.buf.subarray(32 * 2, 32 * 3) }
  get x () { return this.buf.subarray(32 * 3, 32 * 4) }
  get X () { return this.buf.subarray(32 * 4, 32 * 5) }
}

class SpakeServerState {
  static byteLength = 32 + SpakeSharedKeys.byteLength

  constructor (buf) {
    assert(buf.byteLength >= SpakeServerState.byteLength)
    this.buf = buf
    this.sharedKeys = new SpakeSharedKeys(buf.subarray(32))
  }

  get serverValidator () { return this.buf.subarray(32 * 0, 32 * 1) }
}

class SpakeKeys {
  static byteLength = 32 * 5

  constructor (buf) {
    assert(buf.byteLength >= 32 * 5)
    this.buf = buf
  }

  get M () { return this.buf.subarray(32 * 0, 32 * 1) }
  get N () { return this.buf.subarray(32 * 1, 32 * 2) }
  get L () { return this.buf.subarray(32 * 2, 32 * 3) }
  get hK () { return this.buf.subarray(32 * 3, 32 * 4) }
  get hL () { return this.buf.subarray(32 * 4, 32 * 5) }
}

class SpakeValidators {
  static byteLength = 32 * 2

  constructor (buf) {
    assert(buf.byteLength >= 32 * 2)
    this.buf = buf
  }

  get clientValidator () { return this.buf.subarray(32 * 0, 32 * 1) }
  get serverValidator () { return this.buf.subarray(32 * 1, 32 * 2) }
}

module.exports = {
  crypto_spake_DUMMYKEYBYTES,
  crypto_spake_PUBLICDATABYTES,
  crypto_spake_RESPONSE1BYTES,
  crypto_spake_RESPONSE2BYTES,
  crypto_spake_RESPONSE3BYTES,
  crypto_spake_SHAREDKEYBYTES,
  crypto_spake_STOREDBYTES,
  SpakeSharedKeys,
  SpakeClientState,
  SpakeServerState,
  SpakeKeys,
  SpakeValidators
}
