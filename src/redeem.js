const bsv = require('bsv')

/**
 * Redeems a PushDrop transaction output
 * 
 * @param {Object} obj All parameters are given in an object
 * @param {String} obj.prevTxId The ID of the transaction to redeem
 * @param {Number} obj.outputIndex The index of the transaction output to redeem
 * @param {bsv.Script} obj.lockingScript The locking script of the output to redeem
 * @param {Number} obj.outputAmount Number of satoshis in the PushDrop UTXO
 * @param {bsv.PrivateKey} obj.key Private key used to lock the PushDrop UTXO
 * @param {Object} [obj.signSingleOutput] If provided, uses SIGHASH_SINGLE instead of SIGHASH_NONE. The input index must be the same as the output index o this output in the transaction.
 * @param {Number} [obj.signSingleOutput.satoshis] Number of satoshis in the single output to sign
 * @param {bsv.Script} [obj.signSingleOutput.script] Output script of the single output to sign (this COULD be a PushDrop script created with `pushdrop.create`)
 * @param {Number} obj.inputIndex The input in the spending transaction that will unlock the PushDrop UTXO
 * @returns {String} Unlocking script that spends the PushDrop UTXO
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
      script: signSingleOutput.script,
      satoshis: signSingleOutput.satoshis
    }))
    signature = bsv.Transaction.Sighash.sign(
      tx,
      key,
      bsv.crypto.Signature.SIGHASH_FORKID |
        bsv.crypto.Signature.SIGHASH_SINGLE |
        bsv.crypto.Signature.SIGHASH_ANYONECANPAY,
      inputIndex,
      bsv.Script.fromHex(lockingScript),
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
      bsv.Script.fromHex(lockingScript),
      new bsv.crypto.BN(outputAmount)
    )
  }
  return bsv.Script.buildPublicKeyIn(
    signature,
    signature.nhashtype
  ).toHex()
}
