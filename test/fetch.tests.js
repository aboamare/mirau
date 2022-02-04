import chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import fetch from '../src/fetch.js'

chai.should()
chai.use(chaiAsPromised)

const goodUrl = 'https://raw.githubusercontent.com/aboamare/mirau/main/test/data/'
const nonExistingUrl = 'https://nonexists.aboamare.net/aboamare/certificates/'
const path = 'aboamare.x5u'

describe('Fetch tests', function () {
  it('Plain fetch', async function () {
    let resp = await fetch(goodUrl + path)
    resp.should.have.property('ok')
    resp.ok.should.be.true

    resp = fetch(nonExistingUrl + path)
    resp.should.be.rejectedWith(Error)
  })

  it('Fetch with URL rewrite', async function () {
    fetch.addRule(nonExistingUrl, goodUrl)

    let resp = await fetch(goodUrl + path)
    resp.should.have.property('ok')
    resp.ok.should.be.true

    resp = await fetch(nonExistingUrl + path)
    resp.should.have.property('ok')
    resp.ok.should.be.true
  })

  it('Fetch rewrite URL removal', async function () {
    fetch.addRule(nonExistingUrl, goodUrl)

    let resp = await fetch(goodUrl + path)
    resp.should.have.property('ok')
    resp.ok.should.be.true

    resp = await fetch(nonExistingUrl + path)
    resp.should.have.property('ok')
    resp.ok.should.be.true

    fetch.removeRules(goodUrl) //no such rules were added so nothing should change
    
    resp = await fetch(goodUrl + path)
    resp.should.have.property('ok')
    resp.ok.should.be.true

    resp = await fetch(nonExistingUrl + path)
    resp.should.have.property('ok')
    resp.ok.should.be.true    

    fetch.removeRules(nonExistingUrl)

    resp = fetch(nonExistingUrl + path)
    resp.should.be.rejectedWith(Error)
  })
})