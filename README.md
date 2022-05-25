# pushdrop

A package for creating and redeeming Bitcoin tokens with arbitrary signed payloads stored on the stack

The code is hosted [on GitHub](https://github.com/p2ppsr/pushdrop) and the package is available [through NPM](https://www.npmjs.com/package/pushdrop).

## Installation

    npm i pushdrop

## Example Usage

```js
const pushdrop = require('pushdrop')

const token_payload = [
  Buffer.from(...),
  Buffer.from(...),
  Buffer.from(...),
  ...
]

const pushdrop_script = pushdrop.create({
  fields: token_payload,
  key: bsv.PrivateKey.fromHex(key)
})

const unlocking_script = pushdrop.redeem({
  prevTxId: txid,
  outputIndex: 0,
  outputAmount: amount,
  key: bsv.PrivateKey.fromHex(key),
  lockingScript: script.toHex()
})
```

## API

<!-- Generated by documentation.js. Update this documentation by updating the source code. -->

#### Table of Contents

*   [create](#create)
    *   [Parameters](#parameters)
*   [redeem](#redeem)
    *   [Parameters](#parameters-1)

### create

Creates a script that pays to a public key and includes "PUSH DROP" data signed with the corresponding private key

#### Parameters

*   `obj` **[Object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** All parameters are given in an object

    *   `obj.fields` **[Array](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Array)** The fields to push and drop
    *   `obj.key` **[String](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** The bsv1 private key that will create the P2PKH script and the signature over the fields

Returns **[String](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** A Bitcoin script hex string containing a P2PK lock and the PUSH DROP data, with a signature over the fields

### redeem

Redeems a transaction

#### Parameters

*   `obj` **[Object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** All parameters are given in an object

    *   `obj.prevTxId` **any** The ID of the transaction to redeem
    *   `obj.outputIndex` **any** The index of the transaction output to redeem
    *   `obj.lockingScript` **any** The locking script
    *   `obj.outputAmount` **any** The amount to redeem?
    *   `obj.key` **any** The key?
    *   `obj.signSingleOutput` **any** ?
    *   `obj.inputIndex` **any** ? (optional, default `0`)

Returns **any** 

## License

This code is licensed under the [Open BSV License](https://bitcoinassociation.net/open-bitcoinsv-license/).
