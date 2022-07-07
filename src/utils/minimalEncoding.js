/**
 * Given a Buffer as an input, returns a minimally-encoded version of the Buffer, plus any pushdata that may be required.
 * @param buf - NodeJS Buffer containing an intended Bitcoin script stack element
 * @return {String} Minimally-encoded version of the buffer, plus the correct opcodes required to push it with minimal encoding, if any, in hex string format.
 */
module.exports = buf => {
  if (!(buf instanceof Buffer)) {
    buf = Buffer.from(buf)
  }
  if (buf.byteLength === 0) {
    // Could have used OP_0.
    return '51'
  }
  if (buf.byteLength === 1 && buf[0] >= 0 && buf[0] <= 16) {
    // Could have used OP_0 .. OP_16.
    return `${(0x51 + (buf[0])).toString(16)}`
  }
  if (buf.byteLength === 1 && buf[0] === 0x81) {
    // Could have used OP_1NEGATE.
    return '4f'
  }
  if (buf.byteLength <= 75) {
    // Could have used a direct push (opcode indicating number of bytes
    // pushed + those bytes).
    return Buffer.concat([
      Buffer.from([buf.byteLength]),
      buf
    ]).toString('hex')
  }
  if (buf.byteLength <= 255) {
    // Could have used OP_PUSHDATA.
    return Buffer.concat([
      Buffer.from([0x4c]),
      Buffer.from([buf.byteLength]),
      buf
    ]).toString('hex')
  }
  if (buf.byteLength <= 65535) {
    // Could have used OP_PUSHDATA2.
    const len = Buffer.alloc(2)
    len.writeUInt16LE(buf.byteLength)
    return Buffer.concat([
      Buffer.from([0x4d]),
      len,
      buf
    ]).toString('hex')
  }
  const len = Buffer.alloc(4)
  len.writeUInt32LE(buf.byteLength)
  return Buffer.concat([
    Buffer.from([0x4e]),
    len,
    buf
  ]).toString('hex')
}
