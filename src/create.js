const bsv = require('bsv')
const minimalEncoding = require('./utils/minimalEncoding')
const BabbageSDK = require('@babbage/sdk')

const OP_DROP = '75'
const OP_2DROP = '6d'

/**
 * Creates a script that pays to a public key and includes "PUSH DROP" data signed with the corresponding private key
 *
 * @param {Object} obj All parameters are given in an object
 * @param {Array<Buffer|string>} obj.fields The token payload fields to push and drop. Each field is given as a Buffer, or a utf8 string.
 * @param {string|PrivateKey} obj.key The private key that will sign the token payload. Given in WIF or an instance of bsv PrivateKey. If no key is provided, the BabbageSDK will be used as a signing strategy.
 * @param {string|PublicKey} [obj.ownerKey] The owner's public key, whose private key can unlock the token using the `redeem` function. If not provided, the signing key will be used. Given in DER (33- or 65-byte hex), or an instance of bsv1 PublicKey. If no signing private key is provided, the BabbageSDK will be used to derive the ownerKey.
 * @param {string} args.protocolID Specify an identifier for the protocol under which this operation is being performed.
 * @param {string} args.keyID An identifier for the message being signed. During verification, or when retrieving the public key used, the same message ID will be required. This can be used to prevent key re-use, even when the same user is using the same protocol to sign multiple messages.
 * @param {string} [args.description] Describe the high-level operation being performed, so that the user can make an informed decision if permission is needed.
 * @param {string} [args.counterparty=self] If specified, the user with this identity key will also be able to verify the signature, as long as they specify the current user's identity key as their counterparty. Must be a hexadecimal string representing a 33-byte or 65-byte value, "self" or "anyone".
 * @param {string} [args.privileged=false] This indicates whether the privileged keyring should be used for signing, as opposed to the primary keyring.
 *
 * @returns {String} A Bitcoin script hex string containing a P2PK lock and the PUSH DROP data, with a signature over the fields
 */
module.exports = async ({ fields, key, ownerKey, protocolID, keyID, counterparty, privileged, description }) => {
  // Try to convert to BSV key structures
  if (typeof key === 'string') {
    key = bsv.PrivateKey.fromWIF(key)
  }
  if (typeof ownerKey === 'string') {
    ownerKey = bsv.PublicKey.fromString(ownerKey)
  }
  // Set the ownerKey depending on the key & ownerKey provided
  if (key && !ownerKey) {
    ownerKey = key.publicKey
  } else if (!key && !ownerKey) {
    // Get ownerKey from SDK
    ownerKey = bsv.PublicKey.fromString((await BabbageSDK.getPublicKey({
      protocolID,
      keyID,
      description,
      privileged,
      counterparty
    })))
  }

  const lockPart = bsv.Script.buildPublicKeyOut(ownerKey).toHex()
  const dataToSign = Buffer.concat(fields.map(x => {
    if (x instanceof Buffer) {
      return x
    } else {
      return Buffer.from(x)
    }
  }))
  // Sign the data with the SDK if no key is provided
  let signature
  if (!key) {
    signature = await BabbageSDK.createSignature({
      data: Buffer.from(dataToSign),
      protocolID,
      keyID,
      description,
      counterparty,
      privileged
    })
  } else {
    signature = bsv.crypto.ECDSA.sign(
      bsv.crypto.Hash.sha256(dataToSign),
      key
    ).toBuffer()
  }

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
