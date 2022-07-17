const bsv = require('bsv')
const minimalEncoding = require('./utils/minimalEncoding')

const OP_DROP = '75'
const OP_2DROP = '6d'

/**
 * Creates a script that pays to a public key and includes "PUSH DROP" data signed with the corresponding private key
 *
 * @param {Object} obj All parameters are given in an object
 * @param {Array<Buffer|string>} obj.fields The token payload fields to push and drop. Each field is given as a Buffer, or a utf8 string.
 * @param {string|PrivateKey} obj.key The private key that will sign the token payload. Given in WIF or an instance of bsv1 PrivateKey.
 * @param {string|PublicKey} [obj.ownerKey] The owner's public key, whose private key can unlock the token using the `redeem` function. If not provided, the signing key will be used. Given in DER (33- or 65-byte hex), or an instance of bsv1 PublicKey.
 *
 * @returns {String} A Bitcoin script hex string containing a P2PK lock and the PUSH DROP data, with a signature over the fields
 */
module.exports = ({ fields, key, ownerKey }) => {
  if (typeof key === 'string') {
    key = bsv.PrivateKey.fromWIF(key)
  }
  if (typeof ownerKey === 'string') {
    ownerKey = bsv.PublicKey.fromString(ownerKey)
  }
  if (!ownerKey) {
    ownerKey = key.publicKey
  }
  const lockPart = bsv.Script.buildPublicKeyOut(ownerKey).toHex()
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
