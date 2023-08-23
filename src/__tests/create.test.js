/* eslint-env jest */
const create = require('../create')
const bsv = require('babbage-bsv')

const someRandomKeypair = {
  address: '14QaGZW4fG9dfvx3JGj9pwcdzNSqWEYhTi',
  key: bsv.PrivateKey
    .fromWIF('5K4Wq578LC4nYd7oxnzxBcimtQguWJzV7W93UgcDKNL4C3vL5zu')
}

describe('create', () => {
  it('Returns the correct script that passes extra checks', async () => {
    const result = await create({
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
  it('Works with minimally-encoded data', async () => {
    const result = await create({
      fields: [
        Buffer.from('deadbeef2020', 'hex'),
        'hello world',
        'This is a field',
        'here comes field number four',
        Buffer.from('field 5 is a buffer', 'utf8'),
        Buffer.from('00', 'hex'),
        Buffer.from('01', 'hex'),
        Buffer.from('02', 'hex'),
        Buffer.from('0f', 'hex'),
        Buffer.from('10', 'hex'),
        Buffer.from('81', 'hex'),
        Buffer.from('deadbeef2022', 'hex')
      ],
      key: someRandomKeypair.key
    })
    expect(result).toEqual(
      '4104c9d0ddc86380f42c2126e1b71d1006495a1d952189e42b65b087c98286d14182c27b3dba5feb2bce841aef8d88295e6bf5a0be36734874ec72fac4161c021c31ac06deadbeef20200b68656c6c6f20776f726c640f546869732069732061206669656c641c6865726520636f6d6573206669656c64206e756d62657220666f7572136669656c6420352069732061206275666665720051525f604f06deadbeef202246304402204c591eedb0fa6c228482a29872ec09a9279c10cfa3d1c28f186366d8c7996c4a0220225c70ec8bb934db1a42b3852736288eea1930bf0266d9c9ea0f7bf27ad43e6f6d6d6d6d6d6d75'
    )
  })
  it('Works with the lock after the push drop', async () => {
    const result = await create({
      fields: [
        Buffer.from('deadbeef2020', 'hex'),
        'hello world',
        'This is a field',
        'here comes field number four',
        Buffer.from('field 5 is a buffer', 'utf8'),
        Buffer.from('00', 'hex'),
        Buffer.from('01', 'hex'),
        Buffer.from('02', 'hex'),
        Buffer.from('0f', 'hex'),
        Buffer.from('10', 'hex'),
        Buffer.from('81', 'hex'),
        Buffer.from('deadbeef2022', 'hex')
      ],
      key: someRandomKeypair.key,
      lockBefore: false
    })
    expect(result).toEqual(
      '06deadbeef20200b68656c6c6f20776f726c640f546869732069732061206669656c641c6865726520636f6d6573206669656c64206e756d62657220666f7572136669656c6420352069732061206275666665720051525f604f06deadbeef202246304402204c591eedb0fa6c228482a29872ec09a9279c10cfa3d1c28f186366d8c7996c4a0220225c70ec8bb934db1a42b3852736288eea1930bf0266d9c9ea0f7bf27ad43e6f6d6d6d6d6d6d754104c9d0ddc86380f42c2126e1b71d1006495a1d952189e42b65b087c98286d14182c27b3dba5feb2bce841aef8d88295e6bf5a0be36734874ec72fac4161c021c31ac'
    )
  })
  it('Works with no signature', async () => {
    const result = await create({
      fields: [
        Buffer.from('deadbeef2022', 'hex')
      ],
      key: someRandomKeypair.key,
      disableSignature: true
    })
    expect(result).toEqual(
      '4104c9d0ddc86380f42c2126e1b71d1006495a1d952189e42b65b087c98286d14182c27b3dba5feb2bce841aef8d88295e6bf5a0be36734874ec72fac4161c021c31ac06deadbeef202275'
    )
  })
  it('Works with a custom lock', async () => {
    const result = await create({
      fields: [
        Buffer.from('deadbeef2022', 'hex')
      ],
      key: someRandomKeypair.key,
      customLock: 'aaaaaaaabbbbbbbb'
    })
    expect(result).toEqual(
      'aaaaaaaabbbbbbbb06deadbeef2022463044022065b88043757e46f40d73b1ba48bc8c5d7886576e7ade42d0e56e1d88b0011e6c022007f61bc0739c3a0c377538dcb41193163fd69e7e999b907f75f769cff277e65d6d'
    )
  })
  it('Works with a custom lock and no signature', async () => {
    const result = await create({
      fields: [
        Buffer.from('deadbeef2022', 'hex')
      ],
      disableSignature: true,
      customLock: 'aaaaaaaabbbbbbbb'
    })
    expect(result).toEqual(
      'aaaaaaaabbbbbbbb06deadbeef202275'
    )
  })
  it('Works with a custom lock, no signature, and the push drop before the lock', async () => {
    const result = await create({
      fields: [
        Buffer.from('deadbeef2022', 'hex')
      ],
      disableSignature: true,
      lockBefore: false,
      customLock: 'aaaaaaaabbbbbbbb'
    })
    expect(result).toEqual(
      '06deadbeef202275aaaaaaaabbbbbbbb'
    )
  })
  it('Works with data larger than 256 bytes data', async () => {
    const result = await create({
      fields: [
        'So, let me tell you a story. The only requirement of the story is that it is larger than 256 bytes, so it is completely meaningless and you should totally just ignore it and not read any further. Like seriously, stop reading. There is literally no reason for what you are doing right now. How has it come to pass that literally, out of all the things you could be doing in your life, the one thing that appeals to you the MOST is to be reading some random story in some test suite for a random NPM package about pushing and then immediately dropping values from a stack in Bitcoin? Like, what a waste of time. Just iagine how the guy writing this must feel, after writing all of this and then realizing he could have just copy and pasted the same "test" phrase over and over. But no — he decided to write a big long story yelling at people for reading his big long story instead. Why? Because out of all the things he could be doing in his life, the one thing that appeals to him the MOST is to be writing some random story in some random test suite for a random NPM package about pushing and then immediately dropping values from a stack in Bitcoin. Yay. But since you read it to the end like me, the guy who wrote it till the end, I am actually going to give you some life advice. Don\'t listen to crazy people who tell you to stop reading stories that you are enjoying. Curiosity in such times is important. Curiosity defeats nihilism, and cool stories give life its meaning. Even if they happen to be in a silly test suite for—if I do say so myself—a pretty damn cool NPM package.'
      ],
      key: someRandomKeypair.key
    })
    expect(result).toEqual(
      '4104c9d0ddc86380f42c2126e1b71d1006495a1d952189e42b65b087c98286d14182c27b3dba5feb2bce841aef8d88295e6bf5a0be36734874ec72fac4161c021c31ac4d3506536f2c206c6574206d652074656c6c20796f7520612073746f72792e20546865206f6e6c7920726571756972656d656e74206f66207468652073746f72792069732074686174206974206973206c6172676572207468616e203235362062797465732c20736f20697420697320636f6d706c6574656c79206d65616e696e676c65737320616e6420796f752073686f756c6420746f74616c6c79206a7573742069676e6f726520697420616e64206e6f74207265616420616e7920667572746865722e204c696b6520736572696f75736c792c2073746f702072656164696e672e205468657265206973206c69746572616c6c79206e6f20726561736f6e20666f72207768617420796f752061726520646f696e67207269676874206e6f772e20486f772068617320697420636f6d6520746f20706173732074686174206c69746572616c6c792c206f7574206f6620616c6c20746865207468696e677320796f7520636f756c6420626520646f696e6720696e20796f7572206c6966652c20746865206f6e65207468696e6720746861742061707065616c7320746f20796f7520746865204d4f535420697320746f2062652072656164696e6720736f6d652072616e646f6d2073746f727920696e20736f6d65207465737420737569746520666f7220612072616e646f6d204e504d207061636b6167652061626f75742070757368696e6720616e64207468656e20696d6d6564696174656c792064726f7070696e672076616c7565732066726f6d206120737461636b20696e20426974636f696e3f204c696b652c20776861742061207761737465206f662074696d652e204a75737420696167696e6520686f7720746865206775792077726974696e672074686973206d757374206665656c2c2061667465722077726974696e6720616c6c206f66207468697320616e64207468656e207265616c697a696e6720686520636f756c642068617665206a75737420636f707920616e6420706173746564207468652073616d652022746573742220706872617365206f76657220616e64206f7665722e20427574206e6f20e28094206865206465636964656420746f207772697465206120626967206c6f6e672073746f72792079656c6c696e672061742070656f706c6520666f722072656164696e672068697320626967206c6f6e672073746f727920696e73746561642e205768793f2042656361757365206f7574206f6620616c6c20746865207468696e677320686520636f756c6420626520646f696e6720696e20686973206c6966652c20746865206f6e65207468696e6720746861742061707065616c7320746f2068696d20746865204d4f535420697320746f2062652077726974696e6720736f6d652072616e646f6d2073746f727920696e20736f6d652072616e646f6d207465737420737569746520666f7220612072616e646f6d204e504d207061636b6167652061626f75742070757368696e6720616e64207468656e20696d6d6564696174656c792064726f7070696e672076616c7565732066726f6d206120737461636b20696e20426974636f696e2e205961792e204275742073696e636520796f75207265616420697420746f2074686520656e64206c696b65206d652c20746865206775792077686f2077726f74652069742074696c6c2074686520656e642c204920616d2061637475616c6c7920676f696e6720746f206769766520796f7520736f6d65206c696665206164766963652e20446f6e2774206c697374656e20746f206372617a792070656f706c652077686f2074656c6c20796f7520746f2073746f702072656164696e672073746f72696573207468617420796f752061726520656e6a6f79696e672e20437572696f7369747920696e20737563682074696d657320697320696d706f7274616e742e20437572696f736974792064656665617473206e6968696c69736d2c20616e6420636f6f6c2073746f726965732067697665206c69666520697473206d65616e696e672e204576656e20696620746865792068617070656e20746f20626520696e20612073696c6c79207465737420737569746520666f72e280946966204920646f2073617920736f206d7973656c66e2809461207072657474792064616d6e20636f6f6c204e504d207061636b6167652e47304502210080b00bcccb205f5a82082617b59f40fe79c1552db7127a95d0049cf47fae97f4022079f21878c91d54bbf957d284aecaee7a78c25d91af69a550cf9ada243b2402ac6d'
    )
  })
})
