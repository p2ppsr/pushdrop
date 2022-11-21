const decode = require('../decode')
const create = require('../create')
const bsv = require('babbage-bsv')

const someRandomKeypair = {
  address: '14QaGZW4fG9dfvx3JGj9pwcdzNSqWEYhTi',
  key: bsv.PrivateKey
    .fromWIF('5K4Wq578LC4nYd7oxnzxBcimtQguWJzV7W93UgcDKNL4C3vL5zu')
}

describe('decode', () => {
  it('Properly decodes a script that was created', async () => {
    const fields = ['hello', 'world']
    const lockingScript = await create({
      fields,
      key: someRandomKeypair.key
    })
    const decoded = decode({ script: lockingScript, fieldFormat: 'utf8' })
    expect(decoded.fields).toEqual(fields)
    expect(decoded.lockingPublicKey)
      .toEqual(someRandomKeypair.key.publicKey.toString())
  })
})