import * as jose from 'jose'

import Errors from './errors.js'
import { JWT } from './jwt.js'
import { MCPCertificate } from './certificate.js'
import { Options } from './options.js'

const { EntityError, CertificateError} = Errors

export class Attestation {
  constructor (issuer, subject, claims = { mirOk: true }) {
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
    const alg = privateKey.alg || this.issuer.signatureAlgorithm || 'ES384'
    if (privateKey.constructor.name === 'Object') {
      privateKey = await jose.importJWK(privateKey, alg)
    }
    const claims = Object.assign({
      iss: this.issuer.uid,
      sub: this.subject.uid }, 
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

  static RecognizedClaims = ['mirOk', 'mirEndorsed']

  static async fromJWT (token, options = {}) {
    const validationOptions = options instanceof Options ? options : new Options(options)
    const jwt = await JWT.validate(token, {}, validationOptions)

    await MCPCertificate.validate(jwt.chain, jwt.iss, validationOptions)
  
    const claims = this.RecognizedClaims.reduce((result, claim) => {
      if (jwt[claim] !== undefined) {
        result[claim] = jwt[claim]
      }
      return result
    }, {})

    return new this(jwt.chain[0], jwt.sub, claims)

  }  
}

Attestation.RecognizedClaims.forEach(claim => {
  Object.defineProperty(Attestation.prototype, claim, {
    get () {
      return !!this._claims[claim]
    }
  })
})