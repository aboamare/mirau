import chai from 'chai'

chai.should()
const expect = chai.expect

import { Cache } from '../src/cache.js'

describe('Memory cache tests', function () {
  const cache = new Cache({
    maxEntries: 3,
    expireIn: '3 seconds'
  })

  function createEntry(key = 'A') {
    const lc = key.toLowerCase()
    const propName = lc+lc+lc
    return [key, { [propName]: key }]
  }

  async function wait(seconds = 4) {
    return new Promise((resolve) => {
      setTimeout(() => { resolve() }, seconds * 1000)
    })
  }

  this.beforeEach(() => {
    cache.clear()
  })

  it('Set and get non-expired entries', function() {
    cache.set(...createEntry('A'))
    const entry = cache.get('A')
    entry.should.have.property('aaa')
    entry.aaa.should.equal('A')
  })
  it('Exceed capacity, oldest entries should go', function () {
    ['A', 'B', 'C'].forEach(key => cache.set(...createEntry(key)))
    cache.size.should.equal(3)
    cache.set(...createEntry('D'))
    cache.size.should.be.lessThanOrEqual(3)
    expect(cache.get('A')).to.be.undefined
  })

  it('Expired entry should not be found', async function () {
    this.timeout(5000)
    cache.set(...createEntry('A'))
    await wait(4)
    expect(cache.get('A')).to.be.undefined
  })
})