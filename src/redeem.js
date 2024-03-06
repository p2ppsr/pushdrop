const bsv = require('babbage-bsv')
const BabbageSDK = require('@babbage/sdk-ts')

/**
 * Redeems a PushDrop transaction output
 *
 * @param {Object} obj All parameters are given in an object
 * @param {string} obj.prevTxId The ID of the transaction to redeem
 * @param {Number} obj.outputIndex The index of the transaction output to redeem
 * @param {string|bsv.Script} obj.lockingScript The locking script of the output to redeem. Given as a hex string or an instance of bsv1 Script.
 * @param {Number} obj.outputAmount Number of satoshis in the PushDrop UTXO
 * @param {string|bsv.PrivateKey} obj.key Private key that can unlock the PushDrop UTXO's P2PK lock. Given as a WIF string or an instance of bsv1 PrivateKey.
 * @param {string} obj.protocolID Specify an identifier for the protocol under which this operation is being performed.
 * @param {string} obj.keyID An identifier for the message being signed. During verification, or when retrieving the public key used, the same message ID will be required. This can be used to prevent key re-use, even when the same user is using the same protocol to sign multiple messages.
 * @param {string} [obj.description] Describe the high-level operation being performed, so that the user can make an informed decision if permission is needed.
 * @param {string} [obj.counterparty=self] If specified, the user with this identity key will also be able to verify the signature, as long as they specify the current user's identity key as their counterparty. Must be a hexadecimal string representing a 33-byte or 65-byte value, "self" or "anyone".
 * @param {string} [obj.privileged=false] This indicates whether the privileged keyring should be used for signing, as opposed to the primary keyring.
 * @param {Object} [obj.signSingleOutput] If provided, uses SIGHASH_SINGLE instead of SIGHASH_NONE. The input index must be the same as the output index of this output in the transaction.
 * @param {Number} [obj.signSingleOutput.satoshis] Number of satoshis in the single output to sign
 * @param {string|bsv.Script} [obj.signSingleOutput.script] Output script of the single output to sign (this COULD be another PushDrop script created with the `create` function, allowing you to continue/spend/update the token). Given as a hex string or an instance of bsv1 Script.
 * @param {Number} obj.inputIndex The input in the spending transaction that will unlock the PushDrop UTXO
 * @returns {Promise<string>} Unlocking script that spends the PushDrop UTXO
 */
module.exports = async ({
  prevTxId,
  outputIndex,
  lockingScript,
  outputAmount,
  key,
  protocolID,
  keyID,
  description,
  counterparty,
  privileged,
  signSingleOutput,
  inputIndex = 0
}) => {
  if (typeof lockingScript === 'string') {
    lockingScript = bsv.Script.fromBuffer(Buffer.from(lockingScript, 'hex'))
  }
  if (typeof key === 'string') {
    key = bsv.PrivateKey.fromWIF(key)
  }
  const tx = new bsv.Transaction()
  tx.from(new bsv.Transaction.UnspentOutput({
    txid: prevTxId,
    outputIndex,
    script: lockingScript,
    satoshis: outputAmount
  }))
  let signature, sighashType
  if (signSingleOutput) {
    tx.addOutput(new bsv.Transaction.Output({
      script: typeof signSingleOutput.script === 'string'
        ? bsv.Script.fromHex(signSingleOutput.script)
        : signSingleOutput.script,
      satoshis: signSingleOutput.satoshis
    }))
    sighashType = bsv.crypto.Signature.SIGHASH_FORKID |
        bsv.crypto.Signature.SIGHASH_SINGLE |
        bsv.crypto.Signature.SIGHASH_ANYONECANPAY
  } else {
    sighashType = bsv.crypto.Signature.SIGHASH_FORKID |
      bsv.crypto.Signature.SIGHASH_NONE |
      bsv.crypto.Signature.SIGHASH_ANYONECANPAY
  }
  if (!key) {
    const hashbuf = bsv.crypto.Hash.sha256(bsv.Transaction.sighash.sighashPreimage(
      tx,
      sighashType,
      inputIndex,
      lockingScript,
      new bsv.crypto.BN(outputAmount)
    ))
    signature = await BabbageSDK.createSignature({
      data: hashbuf,
      protocolID,
      keyID,
      description,
      counterparty,
      privileged
    })
    signature = bsv.crypto.Signature.fromBuffer(Buffer.from(signature))
    signature.nhashtype = sighashType
  } else {
    signature = bsv.Transaction.Sighash.sign(
      tx,
      key,
      sighashType,
      inputIndex,
      lockingScript,
      new bsv.crypto.BN(outputAmount)
    )
  }
  return bsv.Script.buildPublicKeyIn(
    signature,
    signature.nhashtype
  ).toHex()
}
