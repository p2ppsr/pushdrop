const bsv = require('bsv')
const minimalEncoding = require('./utils/minimalEncoding')

const OP_DROP = '75'
const OP_2DROP = '6d'

/**
 * Creates a script that pays to a public key and includes "PUSH DROP" data signed with the corresponding private key
 *
 * @param {Object} obj All parameters are given in an object
 * @param {Array} obj.fields The fields to push and drop
 * @param {String} obj.key The bsv1 private key that will create the P2PKH script and the signature over the fields
 *
 * @returns {String} A Bitcoin script hex string containing a P2PK lock and the PUSH DROP data, with a signature over the fields
 */
module.exports = ({ fields, key }) => {
  const lockPart = bsv.Script.buildPublicKeyOut(key.publicKey).toHex()
  const dataToSign = Buffer.concat(fields.map(x => {
    if (x instanceof Buffer) {
      return x
    } else {
      return Buffer.from(x)
    }
  }))
  const signature = bsv.crypto.ECDSA.sign(
    bsv.crypto.Hash.sha256(dataToSign),
    key
  ).toBuffer()
  const fieldsWithSig = [
    ...fields,
    signature
  ]
  const pushPart = fieldsWithSig.reduce(
    (acc, el) => acc + minimalEncoding(el),
    ''
  )
  let dropPart = ''
  let undropped = fieldsWithSig.length
  while (undropped > 1) {
    dropPart += OP_2DROP
    undropped -= 2
  }
  if (undropped) {
    dropPart += OP_DROP
  }
  return `${lockPart}${pushPart}${dropPart}`
}
