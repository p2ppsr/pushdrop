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

    *   `obj.fields` **[Array](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Array)<([Buffer](https://nodejs.org/api/buffer.html) | [string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String))>** The token payload fields to push and drop. Each field is given as a Buffer, or a utf8 string.
    *   `obj.key` **([string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String) | PrivateKey)** The private key that will sign the token payload. Given in WIF or an instance of bsv PrivateKey. If no key is provided, the BabbageSDK will be used as a signing strategy.
    *   `obj.ownerKey` **([string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String) | PublicKey)?** The owner's public key, whose private key can unlock the token using the `redeem` function. If not provided, the signing key will be used. Given in DER (33- or 65-byte hex), or an instance of bsv1 PublicKey. If no signing private key is provided, the BabbageSDK will be used to derive the ownerKey.
    *   `obj.protocolID`  
    *   `obj.keyID`  
    *   `obj.counterparty`  
    *   `obj.privileged`  
    *   `obj.description`  

Returns **[String](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** A Bitcoin script hex string containing a P2PK lock and the PUSH DROP data, with a signature over the fields

### redeem

Redeems a PushDrop transaction output

#### Parameters

*   `obj` **[Object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** All parameters are given in an object

    *   `obj.prevTxId` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** The ID of the transaction to redeem
    *   `obj.outputIndex` **[Number](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Number)** The index of the transaction output to redeem
    *   `obj.lockingScript` **([string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String) | bsv.Script)** The locking script of the output to redeem. Given as a hex string or an instance of bsv1 Script.
    *   `obj.outputAmount` **[Number](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Number)** Number of satoshis in the PushDrop UTXO
    *   `obj.key` **([string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String) | bsv.PrivateKey)** Private key that can unlock the PushDrop UTXO's P2PK lock. Given as a WIF string or an instance of bsv1 PrivateKey.
    *   `obj.signSingleOutput` **[Object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)?** If provided, uses SIGHASH_SINGLE instead of SIGHASH_NONE. The input index must be the same as the output index of this output in the transaction.

        *   `obj.signSingleOutput.satoshis` **[Number](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Number)?** Number of satoshis in the single output to sign
        *   `obj.signSingleOutput.script` **([string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String) | bsv.Script)?** Output script of the single output to sign (this COULD be another PushDrop script created with the `create` function, allowing you to continue/spend/update the token). Given as a hex string or an instance of bsv1 Script.
    *   `obj.inputIndex` **[Number](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Number)** The input in the spending transaction that will unlock the PushDrop UTXO (optional, default `0`)
    *   `obj.protocolID`  
    *   `obj.keyID`  
    *   `obj.description`  
    *   `obj.counterparty`  
    *   `obj.privileged`  

Returns **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** Unlocking script that spends the PushDrop UTXO

## License

The license for the code in this repository is the Open BSV License.
