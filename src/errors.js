const Codes = {
  JwtError: {
    TokenError: token => `Error with provided JSON Web Token: ${token.slice(0,20)}...`,
    InvalidNonce: token => `Token has no matching nonce: ${token.nonce}`,
    NoSubject: token => `Token does not have a 'sub' property in the protected header: ${token.slice(0,20)}...`,
    NoCertificate: token => `Token does not have or refer to an MCP Certificate: ${token.slice(0,20)}...`,
    InvalidPublicKey: token => `Token refers to, or contains, a public key that cannot be read: ${token.slice(0,20)}...`,
    WrongKey: token => `Token was not signed with provided public key: ${token.slice(0,20)}...`,
    SubjectNotMrn: sub => `Token 'sub' is not a MRN: ${sub}`,
    UnmetExpectation: exp => `Token ${exp} does not have expected value`
  },
  CertificateError: {
    InvalidCertificate: cert => `Certificate could not be validated: ${cert.fingerprint}`,
    InvalidX5U: x5u => `x5u URL is not valid: ${x5u}`,
    CouldNotParsePEM: pem => `PEM encoded certificate could not be parsed: (${pem.slice(0, 20)}...)`,
    Expired: cert => `Certificate expired at ${cert.validTo}`,
    IssuerNotCA: cert => `Certificate for ${cert.uid} is not intended to be used as CA certificate`,
    IssuerNotMrn: issuer => `Token 'sub' is not a MRN: ${issuer}`,
    NoCertificate: chain => `Certificate chain has no certificate: ${chain}`,
    NotACertificate: cert => `This is not a certificate: ${cert}`,
    NotIssued: (cert, issuerCert) => `Certificate for ${cert.uid} was not issued by certrficate for ${issuerCert.uid} with fingerprint: ${issuerCert.fingerprint}`,
    NotTrusted: cert => `Certificate for ${cert.uid} is not trusted`,
    NotYetValid: cert => `Certificate is valid only from ${cert.validFrom}`,
    OCSPError: (ocspReq) => `Received invalid OCSP response from ${ocspReq.url}`, 
    Revoked: cert => `Certificate for ${cert.uid} has been revoked: ${cert.fingerprint}`,
    SubjectIssuerMismatch: (sub, iss) => `Subject ${sub} cannot have been issued by ${iss}`,
    UidNotMrn: uid => `Certificate UID is not a MRN: ${uid}`,
    UidMismatch: (uidCert, uid) => `Certificate UID ${certUid} does not match: ${uid}`,
    UnknownStatus: cert => `Status of certificate for ${cert.uid} (${cert.fingerprint}) could not be established`
  },
  EntityError: {
    InvalidEntity: entity => `Entity ${entity.uid} does not have necessary properties or has invalid property values`,
    InvalidMatp: entity => `Entity ${entity.uid} does not have valid matp url: ${entity.matp}`,
    InvalidX5u: entity => `Entity ${entity.uid} does not have valid x5u url: ${entity.x5u}`,
    UidNotMrn: uid => `Entity UID is not a MRN: ${uid}`,
    NoCertificateFingerprint: entity => `Entity ${entity.uid} does not have certificate fingerprint`,
    NoX5t256: entity => `Entity ${entity.uid} does not have x5t256 certificate fingerprint`
  }
}

function asErrorFactory (codes, defaultErrorCode) {
  const defaultCode = defaultErrorCode || Object.keys(codes)[0]
  const factory = (code, ...args) => {
    const errCode = typeof codes[code] === 'function' ? code : defaultCode
    const message = (args.length && typeof args[0] === 'string') ? args[0] : codes[errCode](...args)
    const err = Error(message)
    err.code = errCode
    return err  
  }
  const codesAsStrings = {}
  Object.keys(codes).forEach(code => {
    if (typeof codes[code] === 'function') {
      factory[code] = (...args) => factory(code, ...args)
      codesAsStrings[code] = code
    }
  })
  factory.Codes = codesAsStrings
  return factory
}

const exports = Object.keys(Codes).reduce((factories, factoryName) => {
  factories[factoryName] = asErrorFactory(Codes[factoryName])
  return factories
}, {})

export { exports as default }
