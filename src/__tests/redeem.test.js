/* eslint-env jest */
const redeem = require('../redeem')
const bsv = require('babbage-bsv')

const pushDropUnlockableScript = '4104c9d0ddc86380f42c2126e1b71d1006495a1d952189e42b65b087c98286d14182c27b3dba5feb2bce841aef8d88295e6bf5a0be36734874ec72fac4161c021c31ac06deadbeef20200b68656c6c6f20776f726c640f546869732069732061206669656c641c6865726520636f6d6573206669656c64206e756d62657220666f7572136669656c642035206973206120627566666572463044022032d1b9d2747863f718c737952208cf276535cbb9aa306fe4f6149f3d63e3769a022043b6f6226f14b0a05ec15ee7ce78a1300c734999398054349e85b94a0b9a74486d6d6d'
const keyString = '5K4Wq578LC4nYd7oxnzxBcimtQguWJzV7W93UgcDKNL4C3vL5zu'
const key = bsv.PrivateKey.fromWIF(keyString)
const fakeTxid = '7f69c4a9d3daf04686ac6c00db1d7650c5f44dd8fbe7704d0c3c86a0350de0c9'

describe('redeem', () => {
  it('Returns a script', async () => {
    const returnValue = await redeem({
      prevTxId: fakeTxid,
      outputIndex: 2,
      lockingScript: pushDropUnlockableScript,
      outputAmount: 133700,
      key
    })
    expect(returnValue).toEqual('483045022100ae639dc57af54b9f3b812add42451c8c05912ddad7a286cd5930e65751330f9c02205f64b42e2890a15ca644863acb39a04bd3627454b371ba38802b65a87b2b2ebec2')
  })
  it('Returns a script when strings are given', async () => {
    const returnValue = await redeem({
      prevTxId: fakeTxid,
      outputIndex: 2,
      lockingScript: pushDropUnlockableScript,
      outputAmount: 133700,
      key: keyString
    })
    expect(returnValue).toEqual('483045022100ae639dc57af54b9f3b812add42451c8c05912ddad7a286cd5930e65751330f9c02205f64b42e2890a15ca644863acb39a04bd3627454b371ba38802b65a87b2b2ebec2')
  })
  it('Returns a script with signSingleOutput', async () => {
    const returnValue = await redeem({
      prevTxId: fakeTxid,
      outputIndex: 2,
      lockingScript: pushDropUnlockableScript,
      outputAmount: 133700,
      key,
      signSingleOutput: {
        script: bsv.Script.buildPublicKeyOut(key.publicKey),
        satoshis: 9000
      }
    })
    expect(returnValue).toEqual('4830450221009708667f3624251fb9831454d21b9ab23e7cb26b82f6b287c2ff1ce0b82773f6022044952d785acb4b836cc6e1c70fcdfef0a9600122ac7be5bbe8de2b8f9a13fc6ac3')
  })
  it('Returns a script with signSingleOutput using strings', async () => {
    const returnValue = await redeem({
      prevTxId: fakeTxid,
      outputIndex: 2,
      lockingScript: pushDropUnlockableScript,
      outputAmount: 133700,
      key: keyString,
      signSingleOutput: {
        script: '006a',
        satoshis: 1
      }
    })
    expect(returnValue).toEqual('483045022100d3ea7a99c031a54fdf34aefc0245b208b0cae19cea28a9e00cf07f0d6c8d6b0502203399d142b1fb1601bd812aa35a2343a037e6ac26fee6b9e343c1b82b67ab392ec3')
  })
})
