import { X509Certificate } from 'crypto'
import { Certificate }  from 'pkijs' 
import asn1 from 'asn1js'

import cache from './cache.js'
import { OID }  from './mcp-oids.js'
import OCSP from './ocsp.js'
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

function _parseOID (str) {
  function as7Bits (int) {
    const padding = '00000000'
    const bits = int.toString(2)
    return padding.slice(0, 7 - bits.length) + bits
  }
  const match = str.match(/^2\.25\.\{([0-9A-F]+)\}/i)
  if (match) {
    const hexStr = match[1]
    let bits = ''
    for (let i = 0; i < hexStr.length; i = i + 2) {
      bits += as7Bits(parseInt(hexStr.slice(i, i + 2), 16))
    }
    const big = BigInt(`0b${bits}`)
    return `2.25.${big.toString()}`
  }
  return str
}

export class MCPCertificate extends X509Certificate {
  constructor (pem) {
    super(pem)
    
    // Parse as ASN1 based X509 to get important properties
    let b64 = pem.replace(/^\s?-----BEGIN CERTIFICATE-----/, '')
    b64 = b64.replace(/-----END CERTIFICATE-----/, '')
    b64 = b64.replace(/\s+/g, '')
    const buf = Buffer.from(b64, 'base64')
    const asn = asn1.fromBER(buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength))
    const pkiCert = new Certificate({schema: asn.result})
  
    const uidBlock = pkiCert.subject.typesAndValues.find(attrTypeAndValue => attrTypeAndValue.type === OID.UID)
    this.uid = uidBlock ? uidBlock.value.valueBlock.value : undefined
    if (!this.uid || MRN.test(this.uid) !== true) {
      throw CertificateError.SubjectNotMrn(this.subject)
    }

    const ipidBlock = pkiCert.issuer.typesAndValues.find(attrTypeAndValue => attrTypeAndValue.type === OID.UID)
    this.ipid = ipidBlock ? ipidBlock.value.valueBlock.value : undefined

    const extnSubjectAltName = (pkiCert.extensions || []).find(extn => extn.extnID === OID.subjectAltName)
    if (extnSubjectAltName && extnSubjectAltName.parsedValue) {
      const altNames = extnSubjectAltName.parsedValue.altNames || []
      altNames.forEach(altName => {
        const oid = _parseOID(altName.value.valueBlock.value[0].valueBlock.toString())
        const prop = OID[oid]
        if (prop) {
          this[prop] = altName.value[''].valueBlock.value
        }
      })
    }

    const extnAuthKey = (pkiCert.extensions || []).find(extn => extn.extnID === OID.authorityKeyIdentifier)
    this.authorityKeyIdentifier = extnAuthKey.parsedValue.keyIdentifier

    const extnAuthInfoAccess = (pkiCert.extensions || []).find(extn => extn.extnID === OID.authorityInfoAccess)
    if (extnAuthInfoAccess) {
      extnAuthInfoAccess.parsedValue.accessDescriptions.forEach(des => {
        const accessMethod = OID[_parseOID(des.accessMethod)]
        if (accessMethod) {
          this[`${accessMethod}Url`] = des.accessLocation.value
        }
      })
    }

    this.serial = pkiCert.serialNumber
  }

  get _cache () {
    return this.constructor._cache
  }

  get validationOptions () {
    return this.constructor.validationOptions
  }

  cacheAs (status = 'good', kind) {
    if (! this._cache) {
      return
    }
    if (kind === undefined && status === 'trusted') {
      kind = 'trusted'
    }
    if (kind === undefined && this.ca) {
      kind = 'mir'
    }
    const expireIn = this.validationOptions.cache.expireIn[kind]
    const expires = typeof expireIn === 'function' ? expireIn() : undefined
    this._cache.set(this.fingerprint, status, expires)
  }

  async getStatus (options) {
    let result = undefined
    // check cache
    if (this._cache) {
      result = this._cache.get(this.fingerprint)
      if (result) {
        return result
      }
    }

    // try to get OCSP result
    result = await OCSP.getStatus(options.spid, this)
    if (result) {
      return result
    }

    // if in list of trusted certs mark as trusted and cache
    if (options.trusted.has(this.fingerprint)) {
      this.cacheAs('trusted')
      return 'trusted'
    }

    // if applicable get attestations

    return result
  }

  async validate (uid, issuerCert, options) {
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
    if (issuerCert && !mrn.issuedBy(this.ipid)) {
      throw CertificateError.SubjectIssuerMismatch(this.uid, this.ipid)
    }

    const status = await this.getStatus(options)
    if (status && status.revoked) {
      throw CertificateError.Revoked(this)
    }
    if (status === 'trusted') {
      return
    } else if (options.unknown === false || !issuerCert) {
      throw CertificateError.UnknownStatus(this)
    }

    if (issuerCert && !issuerCert.ca) {
      throw CertificateError.IssuerNotCA(issuerCert)
    }
    if (issuerCert && !this.checkIssued(issuerCert)) {
      throw CertificateError.NotIssued(this, issuerCert)
    }

    if (!issuerCert) {
      // this cert is not trusted but perhaps the holder was attested to be ok by an entity that is already trusted
      //TODO: do the OGT-2 dance
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

  static _initCache() {
    const cacheOptions = this.validationOptions.cache
    const clsName = cacheOptions.type || 'Cache'
    this._cache = new cache[clsName]()
    if (!cacheOptions.expireIn) {
      const expireIn = {}
      for (const kind in cacheOptions) {
        if (kind === 'type') {
          continue
        } else if (typeof cacheOptions[kind] === 'string') {
          expireIn[kind] = this._cache.expireIn(cacheOptions[kind])
        } else if (typeof cacheOptions[kind] === 'function') {
          expireIn[kind] = cacheOptions[kind]
        }
      }
      cacheOptions.expireIn = expireIn
    }
  }

  static initialize (options = {spid: 'urn:mrn:mcp:id:aboamare:test:sp'}) {
    Object.assign(this.validationOptions, options)

    if (this.validationOptions.cache) {
      this._initCache()
    }
  }

  static validationOptions = {
    trusted: new Set([]),
    ogtUrl: '',
    cache: {
      certificate: '12 hours',
      mir: '48 hours',
      trusted: '48 hours'
    }
  }

  static trust (certificate) {
    this.validationOptions.trusted.add(certificate.fingerprint)
  }

  static noLongerTrust (certificate) {
    try {
      this.validationOptions.trusted.delete(certificate.fingerprint)
    } catch (err) {
      console.info(err)
    }
  }

  static async validate (chain, uid, options = {}) {
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
      await chain[i].validate(expectedUid, chain[i+1], validationOptions)
      expectedUid = chain[i+1].uid
    }

    const root = chain[chain.length - 1]
    await root.validate(expectedUid, null, validationOptions)
    if (!validationOptions.trusted.includes(root.fingerprint)) {
      //TODO: check OGT
    }
  }
}
