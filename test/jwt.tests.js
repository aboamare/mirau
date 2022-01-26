import chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import * as jose from 'jose'
import { getEngine } from 'pkijs'
import { initCrypto } from '../src/certificate.js'
import Errors from '../src/errors.js'
import { JWT } from '../src/jwt.js'

chai.should()
chai.use(chaiAsPromised)

const { JwtError } = Errors

const testSubject = {
  alg: 'ES384',
  sub: "urn:mrn:mcp:id:aboamare:test:aboamare-spirit",
  jwk: {
    kty: "EC",
    x: "NR1g4V6Q2OOGT5nzgys6iVF8ijcmm7XW4r7zicwSfXaaA7PDekOOEVjeoq6SGJ5l",
    y: "redpwLEmJgOuAJ7drXQblBCBXzMiX-n3sHH7P_9QeP4u4-y87nGCl5EGcDhIqMoP",
    crv: "P-384",
    d: "QjCXRNIa5Xru3zSnKcXyzmGuLo34kEXBKcJRxSa2VssNy470FlM64JWiP0Hm-srk"
  },
  x5u: 'https://raw.githubusercontent.com/aboamare/mirau/main/test/data/aboamare-spirit.x5u'
}

async function createToken (claims, subject, protect = {}) {
  const protectedHeader = Object.assign({
    alg: subject.alg || 'ES384',
    x5u: subject.x5u
  }, protect)
  const privateKey = await jose.importJWK(subject.jwk, subject.alg)
  return new jose.SignJWT(claims)
    .setProtectedHeader(protectedHeader)
    .setIssuedAt()
    .setExpirationTime('2h')
    .sign(privateKey)
}  

async function createKey (namedCurve = 'P-384') {
  try {
    const subtle = getEngine().subtle
    const keyPair = await subtle.generateKey(
      {
        name: "ECDSA",
        namedCurve 
      },
      true,
      ["sign", "verify"]
    )
    const jwkPair = {}
    jwkPair.private = await subtle.exportKey('jwk', keyPair.privateKey)
    jwkPair.public = await subtle.exportKey('jwk', keyPair.publicKey)
    return jwkPair
  } catch (err) {
    console.error(err)
  }
}

describe('JWT Validation', function () {
  before(async () => {
    await initCrypto()
  })

  it('Valid plain MCP authentication token (signed by subject)', async function () {
    const token = await createToken({sub: testSubject.sub}, testSubject)
    const validated = await JWT.validate(token)
    validated.should.be.instanceof(JWT)
    validated.should.have.property('sub')
    validated.sub.should.equal(testSubject.sub)
  })
  it('Token without sub should throw error', async function () {
    const token = await createToken({ nonce: 'noncence' }, testSubject)
    const validated = JWT.validate(token)
    validated.should.be.rejectedWith(JwtError)
  })
  it('Token with nonce', async function () {
    const nonce = 'noncence'
    const token = await createToken({ sub: testSubject.sub }, testSubject, { nonce })
    const validated = await JWT.validate(token, { nonce })
    validated.should.be.instanceof(JWT)
    validated.should.have.property('sub')
    validated.sub.should.equal(testSubject.sub)
  })
  it('Token without nonce should throw error', async function () {
    const nonce = 'noncence'
    const token = await createToken({sub: testSubject.sub}, testSubject)
    const validated = JWT.validate(token, { nonce })
    validated.should.be.rejectedWith(JwtError)
  })
  it('Token without incorrect nonce should throw error', async function () {
    const nonce = 'noncence'
    const token = await createToken({nonce: 'wrong', sub: testSubject.sub}, testSubject)
    const validated = JWT.validate(token, { nonce })
    validated.should.be.rejectedWith(JwtError)
  })
  it('Token signed with another key should throw error', async function () {
    const keyPair = await createKey()
    const subjectWithWrongKey = Object.assign(testSubject, {jwk: keyPair.private})
    const nonce = 'noncence'
    const token = await createToken({nonce: 'wrong', sub: subjectWithWrongKey.sub}, subjectWithWrongKey)
    const validated = JWT.validate(token, { nonce })
    validated.should.be.rejectedWith(JwtError)
  })
})