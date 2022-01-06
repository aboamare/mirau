import Errors from './errors.js'
import { JWT } from './jwt.js'
import { MCPCertificate, MRN } from './certificate.js'

const { EntityError, CertificateError} = Errors

class MCPEntity extends Object {
  constructor (props) {
    super()
    Object.assign(this, props)
    //this.MRN = certificate.subject.DN.UID
  }

  static async fromJWT (token, nonce) {
    const jwt = await JWT.validate(token, { nonce })


    if (jwt.iss && MRN(jwt.sub).issuedBy(jwt.iss) === false) {
      throw new CertificateError.SubjectIssuerMismatch(jwt.sub, jwt.iss)
    }

    await MCPCertificate.validate(jwt.chain, jwt.iss || jwt.sub)
    
  }
}

