const assert = require('nanoassert')

module.exports = class Writer {
  constructor (buf) {
    this._buf = buf
    this._i = 0
  }

  write (buf) {
    this._buf.set(buf, this._i)
    this._i += buf.byteLength
    return this
  }

  u16LE (n) {
    this._buf.writeUInt16LE(n, this._i)
    this._i += 2
    return this
  }

  u32LE (n) {
    this._buf.writeUInt32LE(n, this._i)
    this._i += 4
    return this
  }

  u64LE (n) {
    assert(n <= Number.MAX_SAFE_INTEGER)

    this._buf.writeUInt32LE(n & 0xffffffff, this._i)
    this._buf.writeUInt32LE(Math.floor(n / 2 ** 32), this._i + 4)
    this._i += 8

    return this
  }

  doubleLE (n) {
    this._buf.writeDoubleLE(n, this._i)
    this._i += 8
    return this
  }
}
