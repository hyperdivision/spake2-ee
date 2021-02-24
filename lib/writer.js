const assert = require('nanoassert')

module.exports = class Writer {
  constructor (buf) {
    this._buf = buf
    this._view = new DataView(this._buf.buffer, this._buf.byteOffset)
    this._i = 0
  }

  write (buf) {
    this._buf.set(buf, this._i)
    this._i += buf.byteLength
    return this
  }

  u16LE (n) {
    this._view.setUint16(this._i, n, true)
    this._i += 2
    return this
  }

  u32LE (n) {
    this._view.setUint32(this._i, n, true)
    this._i += 4
    return this
  }

  u64LE (n) {
    assert(n <= Number.MAX_SAFE_INTEGER)

    this._view.setUint32(this._i, n & 0xffffffff, true)
    this._view.setUint32(this._i + 4, Math.floor(n / 2 ** 32), true)
    this._i += 8

    return this
  }
}
