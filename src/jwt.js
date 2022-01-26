import fetch from 'node-fetch'
import * as jose from 'jose'
import pki from 'pkijs'

import { MCPCertificate } from './certificate.js'
import Errors from './errors.js'

const { JwtError } = Errors

export class JWT extends Object {
  constructor (props) {
    super()
    Object.assign(this, props)
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
    const chain = []
    if (unverifiedProtectedHeader.x5u) {
      try {
        const url = new URL(unverifiedProtectedHeader.x5u)
        const response = await fetch(url.toString())
        if (response.ok) {
          const pem = await response.text()
          chain.push(... await MCPCertificate.fromPEM(pem, true))
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
          const jwk = chain[0].jwk
          jwk.alg = jwk.alg || jwk.crv || pki.getEngine().getHashAlgorithm(chain[0].signatureAlgorithm)
          publicKey = await jose.importJWK(jwk)
        }
        //TODO: other means for getting the public key used to sign the token?
      } catch (err) {
        throw JwtError.InvalidPublicKey(token)
      }

      const verificationOptions = Object.assign(this.VerificationOptions, expectations, options)
      const { payload, protectedHeader } = await jose.jwtVerify(token, publicKey, verificationOptions)
  
      for (const exp in expectations) {
        if (unverifiedProtectedHeader[exp] !== expectations[exp]) {
          throw exp === 'nonce' ? JwtError.InvalidNonce(token) : JwtError.UnmetExpectation(exp)
        }
      }
  
      //TODO: check audience, expiration, etc.
      
  
      return new JWT(Object.assign({ chain, raw: token }, payload, protectedHeader))
    } catch (err) {
      if (err instanceof JwtError) {
        throw err
      } else {
        throw JwtError.TokenError(token)
      }
    }

  }

}