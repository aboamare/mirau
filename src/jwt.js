import * as jose from 'jose'
import pki from 'pkijs'

import { MCPCertificate } from './certificate.js'
import { Options } from './options.js'
import Errors from './errors.js'

const { JwtError } = Errors

export class JWT extends Object {
  constructor (props) {
    super()
    Object.assign(this, props)
  }

  static async validate (token, expectations = {}, options = {}) {
    const unverifiedProtectedHeader = jose.decodeProtectedHeader(token)
    const chain = []
    if (unverifiedProtectedHeader.x5u) {
      chain.push(... await MCPCertificate.fetch(unverifiedProtectedHeader.x5u, true))
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

      const verificationOptions = options instanceof Options ? options : new Options(options)
      const { payload, protectedHeader } = await jose.jwtVerify(token, publicKey, verificationOptions.jwt)
  
      for (const exp in expectations) {
        if (unverifiedProtectedHeader[exp] !== expectations[exp]) {
          throw exp === 'nonce' ? JwtError.InvalidNonce(token) : JwtError.UnmetExpectation(exp)
        }
      }
  
      //TODO: check audience, expiration, etc.
      
  
      return new JWT(Object.assign({ chain, raw: token }, payload, protectedHeader))
    } catch (err) {
      if (err.constructor.name === 'JwtError') {
        throw err
      } else {
        console.error(err)
        throw JwtError.TokenError(token)
      }
    }

  }

}