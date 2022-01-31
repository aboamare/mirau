import chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { MCPCertificate } from '../src/certificate.js'
import { Options } from '../src/options.js'
import Errors from '../src/errors.js'
import { Attestation } from '../src/attestations.js'

chai.should()
chai.use(chaiAsPromised)

const { CertificateError } = Errors

const issuer = {
  uid: "urn:mrn:mcp:id:aboamare",
  privateKey: {
    "key_ops":["sign"],
    "ext":true,
    "kty":"EC",
    "x":"LHgzyQDnfiIuSeB5Si6ja_ud1KzooeOTuCVWEcLocMP4S-2zFm6O4HJglTAApEOF",
    "y":"J3w-WwlmO-ugyS4-H40nFPLJUzrjzBDQwJ_9vYJDKTs9OzI9ILUhrS8LeAcAsIn-",
    "crv":"P-384",
    "d":"Xi7GhreXjZAwo5kCjeGFbCFHZ5y7vwwZ4TmaToinovoUbVt5Ee640dzX2mAxYTFp"
  },
  x5uUrl: 'https://raw.githubusercontent.com/aboamare/mirau/main/test/data/aboamare.x5u'
}

const subject = {
  uid: "urn:mrn:mcp:id:aboamare:test",
}

describe('Attestations', function () {
  let validationOptions

  before(async function () {
    await MCPCertificate.initialize()
    validationOptions = new Options({spid: 'urn:mrn:mcp:id:aboamare:test:sp'})
  })

  it('Create attestation', async function () {
    const attn = new Attestation(issuer, subject)
    attn.mirOk.should.be.true
    attn.mirEndorsed.should.be.false
    chai.expect(attn.someRandomClaim).to.be.undefined
  })

  it('Do not accept attestation without trust in issuer', async function () {
    const jwt = await (new Attestation(issuer, subject)).asJWT()
    const attnPromise = Attestation.fromJWT(jwt, validationOptions)
    attnPromise.should.be.rejectedWith(CertificateError)
  })

  it('Accept attestation when allowing unknown issuer', async function () {
    validationOptions.allowUnknownMir = true
    const jwt = await (new Attestation(issuer, subject)).asJWT()
    const attn = await Attestation.fromJWT(jwt, validationOptions)
    validationOptions.allowUnknownMir = false
    attn.mirOk.should.be.true
    attn.mirEndorsed.should.be.false
  })

})