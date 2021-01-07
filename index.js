const lib = require('./lib')

module.exports = {
  Server: require('./server'),
  Client: require('./client'),
  crypto_spake_DUMMYKEYBYTES: lib.crypto_spake_DUMMYKEYBYTES,
  SpakeSharedKeys: lib.SpakeSharedKeys
}
