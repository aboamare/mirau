import { X509Certificate }  from 'crypto'

import { Cache } from './cache.js'
import { OID }  from './mcp-oids.js'
import Errors from './errors.js'

const { CertificateError } = Errors

export class MRN extends String {
  constructor (value) {
    if (!MRN.test(value)) {
      throw TypeError(`${value} is not a valid MCP MIR MRN`)
    }
    super(value)
  }

  get issuer() {
    return new MRN(this.split(':').slice(0, -1).join(':'))
  }
  /**
   * Check if this MRN is in the subspace of an entity that would have the given value as its own MRN.
   * 
   * @param {*} value 
   */
  issuedBy (value) {
    return this.issuer == value.toString()
  }
  static reMrn = /^urn:mrn:mcp:id(:[_-a-z0-9.]+)+/i

  static test (value) {
    return this.reMrn.test(value)
  }
}

export class MCPCertificate extends  X509Certificate {
  constructor (pem) {
    super(pem)

    // set the uid
    const match = this.subject.match(/UID=(.+),?/)
    if (!match) {
      throw CertificateError.SubjectNotMrn(this.subject)
    }
    this.uid = match[1]
  }

  get ipid () {
    if (this._ipid) {
      return this._ipid
    }
    const match = this.issuer.match(/UID=(.+),?/)
    this._ipid = match ? match[1] : undefined
  }

  async get status () {
    // check cache

    // try to get OCSP result

    // if in list of trusted certs mark as trusted and cache

    // if applicable get attestations
  }

  validate (uid, issuerCert, options) {
    if (uid && this.uid !== uid) {
      throw CertificateError.UidMismatch(this.uid, uid)
    }

    const now = new Date()
    if (this.validTo < now) {
      throw CertificateError.Expired(this)
    }
    if (this.validFrom > now) {
      throw CertificateError.NotYetValid(this)
    }

    const mrn = new MRN(this.uid)
    if (!mrn.issuedBy(this.ipid)) {
      throw CertificateError.SubjectIssuerMismatch(this.uid, this.ipid)
    }

    const status = await this.getStatus()
    if (status.trusted) {
      return
    }
    if (status.revoked) {
      throw CertificateError.Revoked(this)
    }

    if (issuerCert && !issuerCert.ca) {
      throw CertificateError.IssuerNotCA(issuerCert)
    }
    if (issuerCert && !this.checkIssued(issuerCert)) {
      throw CertificateError.NotIssued(this, issuerCert)
    }
  }

  static fromPEM (pem, asArray = false) {
    const certificates = []
    const chunks = pem.match(/-----BEGIN CERTIFICATE-----\s([\n\ra-zA-Z0-9/+=]+)-----END CERTIFICATE-----/g)
    chunks.forEach(chunk => {
      try {
        certificates.push(new MCPCertificate(chunk))
      } catch (err) {
        console.warn(err)
      }
    })
    return certificates.length === 1 && asArray === false ? certificates[0] : certificates
  }

  static validationOptions = {
    trusted: [],
    ogtUrl: '',
    cache: {
      certificate: '12 hours',
      mir: '48 hours',
      trusted: '48 hours'
    }
  }

  static validate (chain, uid, options = {}) {
    const validationOptions = Object.assign({}, this.validationOptions, options)
    if (! (Array.isArray(chain) && chain.length > 0)) {
      throw CertificateError.NoCertificate(chain)
    }
    chain.forEach(cert => {
      if (! cert instanceof MCPCertificate) {
        throw CertificateError.NotACertificate(cert)
      }
    })
    let expectedUid = uid
    for (let i = 0; i < chain.length - 1; i++) {
      chain[i].validate(expectedUid, chain[i+1], validationOptions)
      expectedUid = chain[i+1].uid
    }

    const root = chain[chain.length - 1]
    root.validate(expectedUid, null, validationOptions)
    if (!validationOptions.trusted.includes(root.fingerprint)) {
      //TODO: check OGT
    }
  }
}
