const bsv = require('babbage-bsv')
const minimalEncoding = require('./utils/minimalEncoding')
const BabbageSDK = require('@babbage/sdk-ts')

const OP_DROP = '75'
const OP_2DROP = '6d'

/**
 * Creates a script that pays to a public key and includes "PUSH DROP" data signed with the corresponding private key
 *
 * @param {Object} obj All parameters are given in an object
 * @param {Array<Buffer|string>} obj.fields The token payload fields to push and drop. Each field is given as a Buffer, or a utf8 string.
 * @param {string|PrivateKey} obj.key The private key that will sign the token payload. Given in WIF or an instance of bsv PrivateKey. If no key is provided, the BabbageSDK will be used as a signing strategy.
 * @param {string|PublicKey} [obj.ownerKey] The owner's public key, whose private key can unlock the token using the `redeem` function. If not provided, the signing key will be used. Given in DER (33- or 65-byte hex), or an instance of bsv1 PublicKey. If no signing private key is provided, the BabbageSDK will be used to derive the ownerKey.
 * @param {string} obj.protocolID Specify an identifier for the protocol under which this operation is being performed.
 * @param {string} obj.keyID An identifier for the message being signed. During verification, or when retrieving the public key used, the same message ID will be required. This can be used to prevent key re-use, even when the same user is using the same protocol to sign multiple messages.
 * @param {string} [obj.description] Describe the high-level operation being performed, so that the user can make an informed decision if permission is needed.
 * @param {string} [obj.counterparty=self] If specified, the user with this identity key will also be able to verify the signature, as long as they specify the current user's identity key as their counterparty. Must be a hexadecimal string representing a 33-byte or 65-byte value, "self" or "anyone".
 * @param {string} [obj.privileged=false] This indicates whether the privileged keyring should be used for signing, as opposed to the primary keyring.
 * @param {Boolean} [obj.counterpartyCanVerifyMyOwnership=false] Indicates whether the token is owned by its creator, assuming `protocolID` and `keyID` are being used.
 * @param {String} [obj.customLock] If provided, the lock portion of the script will be set to this custom value, and the normal P2PK lock will not be used.
 * @param {Boolean} [obj.disableSignature] If provided, no signature will be applied to the PushDrop token payload.
 * @param {Boolean} [obj.lockBefore=true] If set to false, the lock will be after the push and drop parts of the script.
 * @param {Boolean} [obj.ownedByCreator=false] DEPRECATED - use counterpartyCanVerifyMyOwnership. Retained for backward-compatibility
 *
 * @returns {Promise<string>} A Bitcoin script hex string containing a P2PK lock and the PUSH DROP data, with a signature over the fields
 */
module.exports = async ({
  fields, key, ownerKey, protocolID, keyID, counterparty, ownedByCreator, counterpartyCanVerifyMyOwnership, privileged, description, disableSignature, lockBefore = true, customLock
} = {}) => {
  let lockPart
  if (!customLock) {
    ownedByCreator = counterpartyCanVerifyMyOwnership
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
        counterparty,
        forSelf: ownedByCreator
      })))
    }

    lockPart = bsv.Script.buildPublicKeyOut(ownerKey).toHex()
  } else {
    lockPart = customLock
  }

  let fieldsCopy
  if (!disableSignature) {
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

    fieldsCopy = [
      ...fields,
      signature
    ]
  } else {
    fieldsCopy = [...fields]
  }
  const pushPart = fieldsCopy.reduce(
    (acc, el) => acc + minimalEncoding(el),
    ''
  )
  let dropPart = ''
  let undropped = fieldsCopy.length
  while (undropped > 1) {
    dropPart += OP_2DROP
    undropped -= 2
  }
  if (undropped) {
    dropPart += OP_DROP
  }
  if (lockBefore) {
    return `${lockPart}${pushPart}${dropPart}`
  } else {
    return `${pushPart}${dropPart}${lockPart}`
  }
}
