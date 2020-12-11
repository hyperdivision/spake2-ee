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

  doubleLE (n) {
    this._buf.writeDoubleLE(n, this._i)
    this._i += 8
    return this
  }
}
