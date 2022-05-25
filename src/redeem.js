const bsv = require('bsv')

/**
 * Redeems a transaction
 * 
 * @param {Object} obj All parameters are given in an object
 * @param {*} obj.prevTxId The ID of the transaction to redeem
 * @param {*} obj.outputIndex The index of the transaction output to redeem
 * @param {*} obj.lockingScript The locking script
 * @param {*} obj.outputAmount The amount to redeem?
 * @param {*} obj.key The key?
 * @param {*} obj.signSingleOutput ?
 * @param {*} obj.inputIndex ?
 * @returns {*} 
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
