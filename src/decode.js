const bsv = require('babbage-bsv')

const OP_DROP = 117
const OP_2DROP = 109

/**
 * Given a PushDrop locking script, returns the fields and lockingKey that were used to create it.
 * 
 * If an invalid (non-PushDrop) script is provided, the return value is **undefined**. Only valid PushDrop scripts will be properly decoded. 
 *
 * @param {Object} obj All parameters are given in an object
 * @param {String} obj.script The PushDrop locking script to decode
 * @param {String} [obj.fieldFormat=hex] The format of the fields, either "hex", "base64", "utf8" or "buffer"
 *
 * @returns {Object} The decoded object, containing `fields`, `signature` and `lockingPublicKey`
 */
module.exports = ({ script, fieldFormat = 'hex' }) => {
  const parsedScript = bsv.Script.fromHex(script)
  const lockingPublicKey = parsedScript.chunks[0].buf.toString('hex')
  const fields = []
  let signature
  for (let i = 2; i < parsedScript.chunks.length; i++) {
    const nextOpcode = parsedScript.chunks[i + 1].opcodenum
    // If the next value is DROP or 2DROP then this is the signature
    if (nextOpcode === OP_DROP || nextOpcode === OP_2DROP) {
      signature = parsedScript.chunks[i].buf.toString('hex')
      break
    }
    let chunk = parsedScript.chunks[i].buf
    if (!chunk) {
      if (parsedScript.chunks[i].opcodenum >= 80 && parsedScript.chunks[i].opcodenum <= 95) {
        chunk = Buffer.from([parsedScript.chunks[i].opcodenum - 80])
      }
    }
    if (fieldFormat === 'buffer') {
      fields.push(chunk)
    } else {
      fields.push(chunk.toString(fieldFormat))
    }
  }
  return {
    fields,
    lockingPublicKey,
    signature
  }
}
