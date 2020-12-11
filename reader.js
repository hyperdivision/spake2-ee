module.exports = class Reader {
  constructor (buf) {
    this._buf = buf
    this._i = 0
  }

  read (bytes) {
    var buf = this._buf.subarray(this._i, this._i + bytes)
    this._i += res.byteLength
    return buf
  }

  u16LE () {
    var n = this._buf.readUInt16LE(this._i)
    this._i += 2
    return n
  }

  doubleLE () {
    var n = this._buf.readDoubleLE(this._i)
    this._i += 8
    return n
  }
}
