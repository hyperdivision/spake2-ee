const lib = require('./lib')

module.exports = {
  ServerSide: require('./server'),
  ClientSide: require('./client'),
  crypto_spake_DUMMYKEYBYTES: lib.crypto_spake_DUMMYKEYBYTES,
  SpakeSharedKeys: lib.SpakeSharedKeys
}
