import Errors from './errors.js'
import { MRN } from './mrn.js'
import { JWT } from './jwt.js'
import { MCPCertificate } from './certificate.js'

const { EntityError, CertificateError} = Errors

export class MCPEntity extends Object {
  constructor (props = {}) {
    super()
    Object.assign(this, props)
  }

  get mrn () {
    return new MRN(this.uid)
  }
  
  static RecognizedProperties = [
    'uid',
    'ipid',
    'x5uUrl',
    'ocsp',
    'matp',
    'email',
    'name',
    'country',
    'organization',
    'unit',
    'callSign',
    'flagSate',
    'homePort',
    'imoNumber',
    'mmsi',
    'secondaryMRN',
    'url'
  ]

  static async fromJWT (token, nonce) {
    const jwt = await JWT.validate(token, { nonce })

    if (!jwt.sub) {
      throw JwtError.NoSubject(jwt.raw)
    }
    if (!MRN.test(jwt.sub)) {
      throw JwtError.SubjectNotMrn(jwt.sub)
    }

    if (jwt.iss && MRN(jwt.sub).issuedBy(jwt.iss) === false) {
      throw new CertificateError.SubjectIssuerMismatch(jwt.sub, jwt.iss)
    }

    await MCPCertificate.validate(jwt.chain, jwt.iss || jwt.sub)
    
    const subjectCert = chain[0].uid === jwt.sub ? chain[0] : {}
    const properties = this.RecognizedProperties.reduce((props, propName) => {
      const propValue = subjectCert[propName] || jwt[propName]
      if (propValue !== undefined) {
        props[propName] = propValue
      }
      return props
    }, {})
    return new this(properties)
  }
}

