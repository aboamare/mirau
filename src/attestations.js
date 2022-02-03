import * as jose from 'jose'

import Errors from './errors.js'
import { JWT } from './jwt.js'
import { MCPCertificate } from './certificate.js'
import { MRN } from './mrn.js'
import { Options } from './options.js'

const { EntityError, CertificateError} = Errors

export class Attestation {
  constructor (issuer, subject, claims = { mirOk: true }) {
    if (! MRN.test(issuer.uid)) {
      throw EntityError.UidNotMrn(issuer.uid)
    }
    if (! MRN.test(subject.uid)) {
      throw EntityError.UidNotMrn(subject.uid)
    }
    if (! subject.x5t256) {
      throw EntityError.NoX5t256(subject)
    }
    this.issuer = issuer
    this.subject = subject
    this._claims = claims
  }

  async asJWT (options = { privateKey: undefined, expiration: '30d' }) {
    options = Object.assign({expiration: '30d'}, options)
    let privateKey = options.privateKey || this.issuer.privateKey
    if (!privateKey) {
      throw Error('Cannot create attestation without private key')
    }
    const alg = privateKey.alg || this.issuer.algorithm || 'ES384'
    if (privateKey.constructor.name === 'Object') {
      privateKey = await jose.importJWK(privateKey, alg)
    }
    const claims = Object.assign({
        iss: this.issuer.uid,
        sub: this.subject.uid,
        subX5t256: this.subject.x5t256
      },
      this._claims
    )
    const protectedHeader = {
      alg,
      x5u: this.issuer.x5uUrl
    }
    const jwt = await new jose.SignJWT(claims)
    .setProtectedHeader(protectedHeader)
    .setIssuedAt()
    .setExpirationTime(options.expiration)
    .sign(privateKey)

    return jwt
  }

  asserts (subject, claim) {
    return this.subject === subject && this[claim] === true
  }

  static RecognizedClaims = ['mirOk', 'mirEndorsed']

  static async fromJWT (token, options = {}) {
    const validationOptions = options instanceof Options ? options : new Options(options)
    const jwt = await JWT.validate(token, {}, validationOptions)

    await MCPCertificate.validate(jwt.chain, jwt.iss, validationOptions)
  
    const subject = {uid: jwt.sub}
    if (jwt.subX5t256) {
      subject.x5t256 = jwt.subX5t256
    }
    const claims = this.RecognizedClaims.reduce((result, claim) => {
      if (jwt[claim] !== undefined) {
        result[claim] = jwt[claim]
      }
      return result
    }, {})

    return new this(jwt.chain[0], subject, claims)
  }
}

Attestation.RecognizedClaims.forEach(claim => {
  Object.defineProperty(Attestation.prototype, claim, {
    get () {
      return !!this._claims[claim]
    }
  })
})