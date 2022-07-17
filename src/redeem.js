const bsv = require('bsv')

/**
 * Redeems a PushDrop transaction output
 * 
 * @param {Object} obj All parameters are given in an object
 * @param {string} obj.prevTxId The ID of the transaction to redeem
 * @param {Number} obj.outputIndex The index of the transaction output to redeem
 * @param {string|bsv.Script} obj.lockingScript The locking script of the output to redeem. Given as a hex string or an instance of bsv1 Script.
 * @param {Number} obj.outputAmount Number of satoshis in the PushDrop UTXO
 * @param {string|bsv.PrivateKey} obj.key Private key that can unlock the PushDrop UTXO's P2PK lock. Given as a WIF string or an instance of bsv1 PrivateKey.
 * @param {Object} [obj.signSingleOutput] If provided, uses SIGHASH_SINGLE instead of SIGHASH_NONE. The input index must be the same as the output index of this output in the transaction.
 * @param {Number} [obj.signSingleOutput.satoshis] Number of satoshis in the single output to sign
 * @param {string|bsv.Script} [obj.signSingleOutput.script] Output script of the single output to sign (this COULD be another PushDrop script created with the `create` function, allowing you to continue/spend/update the token). Given as a hex string or an instance of bsv1 Script.
 * @param {Number} obj.inputIndex The input in the spending transaction that will unlock the PushDrop UTXO
 * @returns {string} Unlocking script that spends the PushDrop UTXO
 */
module.exports = ({
  prevTxId,
  outputIndex,
  lockingScript,
  outputAmount,
  key,
  signSingleOutput,
  inputIndex = 0
}) => {
  if (typeof lockingScript === 'string') {
    lockingScript = bsv.Script.fromHex(lockingScript)
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
  let signature
  if (signSingleOutput) {
    tx.addOutput(new bsv.Transaction.Output({
      script: typeof signSingleOutput.script === 'string'
        ? bsv.Script.fromHex(signSingleOutput.script)
        : signSingleOutput.script,
      satoshis: signSingleOutput.satoshis
    }))
    signature = bsv.Transaction.Sighash.sign(
      tx,
      key,
      bsv.crypto.Signature.SIGHASH_FORKID |
        bsv.crypto.Signature.SIGHASH_SINGLE |
        bsv.crypto.Signature.SIGHASH_ANYONECANPAY,
      inputIndex,
      lockingScript,
      new bsv.crypto.BN(outputAmount)
    )
  } else {
    signature = bsv.Transaction.Sighash.sign(
      tx,
      key,
      bsv.crypto.Signature.SIGHASH_FORKID |
        bsv.crypto.Signature.SIGHASH_NONE |
        bsv.crypto.Signature.SIGHASH_ANYONECANPAY,
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
