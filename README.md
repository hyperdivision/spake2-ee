# SPAKE2-EE

Implementation of SPAKE2-EE password authenticated key agreement protocol described [here](https://moderncrypto.org/mail-archive/curves/2015/000424.html)

## Installation

```
npm install --save spake2-ee
```

## Usage
```js
const { Client, SpakeSharedKeys } = require('spake2-ee')

const pwd = Buffer.from('password')

const server = new Server(Buffer.from('serverId'))
const client = new Client(Buffer.from('clientId'))

server.register(pwd, OPS, MEM, Buffer.from('579daa4d7bf3ca0e0b6c48b90c4ec515', 'hex'))

// server initiates protocol
const public = server.init()

// send to server
const step = client.generate(public, pwd)

// server processes response
const response1 = server.respond(client.id, step1)

// send result to server, store sharedKeys safely
const sharedKeys = new SpakeSharedKeys()
const step2 = client.finalise(sharedKeys, server.id, res)

// server verifies result and stores key
const serverSharedKeys = server.finalise(step2)
```

## API

### Server

Class implementing server-side logic.

#### `const server = new Server(serverId)`

Instantiate a server. `serverId` should be passed as a `buffer` or `TypedArray`.

Calling `server.id` will return the server's id.

#### `const publicData = server.register(pwd, opslimit, memlimit)`

Server registers a user and their password. `pwd` should be a `buffer`, opslimit and memlimit are constants passed to argon2id password hashing algorithm, see [sodium-native docs](https://sodium-friends.github.io/docs/docs/passwordhashing#crypto_pwhash) for appropriate constants.

#### `const res = server.respond(clientId, msg)`

Respond to a registered user initiating a key agreement protocol. `clientId` shoudl be a `buffer` or `TypedArray`, `msg` should be a `buffer` or `TypedArray` received from the client.

Returns the response for the client if their message is correctly formed, otherwise an error will throw.

#### `const keys = server.finalise(msg)`

Finalise the protocol. Return the shared secrets if the protocol has been executed correctly, otherwsie an error will throw.

### Client

Class implementing client-side logic.

#### `const client = new Client(clientId)`

Instantiate a client. `clientId` should be passed as a `buffer` or `TypedArray`.

Calling `client.id` will return the client's id.

#### `const init = client.generate(publicData, pwd)`

Initiate a key agreement protocol using the `publicData` obtained during registration. `pwd` should be a `buffer` or `TypedArray` representing the password used to register with the server.

#### `const res = client.finalise(sharedKeys, serverId, msg)`

Complete the key agreement protocol and store the keys into `sharedkeys`, which must be an instance of `SpakeSharedKeys`. `serverId` should be passed as a `buffer` or `TypedArray` and `msg` should be the exact output of `server.respond`

An error will be thrown if the server's response is malformed.

### Shared Keys

#### `const keys = new SpakeSharedKeys()`

A class storing the derived shared secrets.

#### `keys.serverSk`

Server's secret

#### `keys.clientSk`

Client's secret
