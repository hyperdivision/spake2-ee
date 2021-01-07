module.exports = class Reader {
  constructor (buf) {
    this._buf = buf
    this._view = new DataView(this._buf.buffer)
    this._i = 0
  }

  read (bytes) {
    const buf = this._buf.subarray(this._i, this._i + bytes)
    this._i += bytes
    return buf
  }

  u16LE () {
    const n = this._view.getUint16(this._i, true)
    this._i += 2
    return n
  }

  u32LE () {
    const n = this._view.getUint32(this._i, true)
    this._i += 4
    return n
  }

  u64LE () {
    let n = this._view.getUint32(this._i, true)
    n += this._view.getUint32(this._i + 4, true) * 2 ** 32
    this._i += 8

    return n
  }
}
