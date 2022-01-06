import fetch from 'node-fetch'
import * as jose from 'jose'
import { MCPCertificate, MRN } from './certificate.js'
import Errors from './errors.js'

const { JwtError } = Errors

export class JWT extends Object {
  constructor (token) {
    super()
    Object.assign(this, token)
  }

  static VerificationOptions = {
    algorithms: ['ES384', 'ES256'],
    clockTolerance: '30 seconds',
    maxTokenAge: '5 minutes'
  }

  static allowOldTokens () {
    delete this.VerificationOptions.clockTolerance
    delete this.VerificationOptions.maxTokenAge
  }

  static async validate (token, expectations = {}, options = {}) {
    const unverifiedProtectedHeader = jose.decodeProtectedHeader(token)
    if (expectations.nonce && unverifiedProtectedHeader.nonce !== expectations.nonce) {
      throw JwtError.InvalidNonce(token, expectations.nonce)
    }

    //TODO: check audience, expiration, etc.
    
    const chain = []
    if (unverifiedProtectedHeader.x5u) {
      try {
        const url = new URL(unverifiedProtectedHeader.x5u)
        const response = await fetch(url.toString())
        if (response.ok) {
          const pem = await response.text()
          chain.push(...MCPCertificate.fromPEM(pem, true))
        } else {
          throw JwtError.InvalidX5U(unverifiedProtectedHeader.x5u)
        }
      } catch (err) {
        if (err instanceof TypeError) {
          throw JwtError.InvalidX5U(unverifiedProtectedHeader.x5u)
        } else {
          throw err
        }
      }
    }
    //TODO: check for x5c

    try {
      let publicKey
      try {
        if (chain.length) {
          publicKey = chain[0].publicKey
          const jwk = publicKey.export({format: 'jwk'})
          jwk.alg = publicKey.asymmetricKeyDetails.namedCurve || publicKey.asymmetricKeyDetails.hashAlgorithm
          publicKey = await jose.importJWK(jwk)
        }
        //TODO: other means for getting the public key used to sign the token?
      } catch (err) {
        throw JwtError.InvalidPublicKey(token)
      }

      const verificationOptions = Object.assign(this.VerificationOptions, expectations, options)
      const { payload, protectedHeader } = await jose.jwtVerify(token, publicKey, verificationOptions)
  
      const tokenSubject = payload.sub
      if (!tokenSubject) {
        throw JwtError.NoSubject(payload)
      }
      if (!MRN.test(tokenSubject)) {
        throw JwtError.SubjectNotMrn(tokenSubject)
      }
      
      return new JWT(Object.assign({ chain }, payload, protectedHeader))
    } catch (err) {
      if (err instanceof JwtError) {
        throw err
      } else {
        throw JwtError.TokenError(token)
      }
    }

  }

}