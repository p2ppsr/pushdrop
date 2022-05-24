const bsv = require('bsv')

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
