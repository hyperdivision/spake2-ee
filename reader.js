module.exports = class Reader {
  constructor (buf) {
    this._buf = buf
    this._i = 0
  }

  read (bytes) {
    var buf = this._buf.subarray(this._i, this._i + bytes)
    this._i += bytes
    return buf
  }

  u16LE () {
    var n = this._buf.readUInt16LE(this._i)
    this._i += 2
    return n
  }

  u32LE () {
    var n = this._buf.readUInt32LE(this._i)
    this._i += 4
    return n
  }

  u64LE () {
    var n = this._buf.readUInt32LE(this._i)
    n += this._buf.readUInt32LE(this._i + 4) * 2 ** 32
    this._i += 8

    return n
  }

  doubleLE () {
    var n = this._buf.readDoubleLE(this._i)
    this._i += 8
    return n
  }
}
