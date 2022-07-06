/* eslint-env jest */
const create = require('../create')
const bsv = require('bsv')

const someRandomKeypair = {
  address: '14QaGZW4fG9dfvx3JGj9pwcdzNSqWEYhTi',
  key: bsv.PrivateKey
    .fromWIF('5K4Wq578LC4nYd7oxnzxBcimtQguWJzV7W93UgcDKNL4C3vL5zu')
}

describe('create', () => {
  it('Returns the correct script that passes extra checks', () => {
    const result = create({
      fields: [
        Buffer.from('deadbeef2020', 'hex'),
        'hello world',
        'This is a field',
        'here comes field number four',
        Buffer.from('field 5 is a buffer', 'utf8')
      ],
      key: someRandomKeypair.key
    })
    expect(result).toEqual(
      '4104c9d0ddc86380f42c2126e1b71d1006495a1d952189e42b65b087c98286d14182c27b3dba5feb2bce841aef8d88295e6bf5a0be36734874ec72fac4161c021c31ac06deadbeef20200b68656c6c6f20776f726c640f546869732069732061206669656c641c6865726520636f6d6573206669656c64206e756d62657220666f7572136669656c642035206973206120627566666572463044022032d1b9d2747863f718c737952208cf276535cbb9aa306fe4f6149f3d63e3769a022043b6f6226f14b0a05ec15ee7ce78a1300c734999398054349e85b94a0b9a74486d6d6d'
    )
    const resultScript = bsv.Script.fromHex(result)
    const signature = resultScript.chunks[7].buf
    expect(bsv.crypto.ECDSA.verify(
      bsv.crypto.Hash.sha256(Buffer.concat([
        Buffer.from('deadbeef2020', 'hex'),
        Buffer.from('hello world', 'utf8'),
        Buffer.from('This is a field', 'utf8'),
        Buffer.from('here comes field number four', 'utf8'),
        Buffer.from('field 5 is a buffer', 'utf8')
      ])),
      bsv.crypto.Signature.fromBuffer(signature),
      someRandomKeypair.key.publicKey
    )).toEqual(true)
    const publicKey = resultScript.chunks[0].buf
    expect(someRandomKeypair.key.publicKey.toBuffer()).toEqual(publicKey)
  })
  it('Works with minimally-encoded data', () => {
    const result = create({
      fields: [
        Buffer.from('deadbeef2020', 'hex'),
        'hello world',
        'This is a field',
        'here comes field number four',
        Buffer.from('field 5 is a buffer', 'utf8'),
        Buffer.from('00', 'hex'),
        Buffer.from('0f', 'hex'),
        Buffer.from('81', 'hex'),
        Buffer.from('deadbeef2022', 'hex')
      ],
      key: someRandomKeypair.key
    })
    expect(result).toEqual(
      '4104c9d0ddc86380f42c2126e1b71d1006495a1d952189e42b65b087c98286d14182c27b3dba5feb2bce841aef8d88295e6bf5a0be36734874ec72fac4161c021c31ac06deadbeef20200b68656c6c6f20776f726c640f546869732069732061206669656c641c6865726520636f6d6573206669656c64206e756d62657220666f7572136669656c64203520697320612062756666657281964f06deadbeef2022463044022078f423aa86dc1acc4dfabf0ee0f645ac4e22ccdba00d948fae38278398241392022023b610b69cc5c1af453603e88f73bd04fc3a5ea5ef583aa6c7b90d64eb8184256d6d6d6d6d'
    )
  })
})
