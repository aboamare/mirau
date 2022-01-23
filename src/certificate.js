import pki  from 'pkijs' 
import asn1 from 'asn1js'
import base64 from 'base64-js'

import cache from './cache.js'
import { MRN } from  './mrn.js'
import { OID }  from './mcp-oids.js'
import OCSP from './ocsp.js'
import Errors from './errors.js'

const { CertificateError } = Errors

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

export async function initCrypto() {
  const engine = pki.getEngine()
  if (!engine.subtle) {
    try {
      const nodeCrypto = await import('crypto')
      pki.setEngine('node', nodeCrypto.webcrypto, nodeCrypto.webcrypto.subtle)
    } catch (err) {
      throw Error('Crypto engine support is not available')
    }
  }
}

export class MCPCertificate extends pki.Certificate {
  constructor (pem) {    
    let b64 = pem.replace(/^\s?-----BEGIN CERTIFICATE-----/, '')
    b64 = b64.replace(/-----END CERTIFICATE-----/, '')
    b64 = b64.replace(/\s+/g, '')
    const asn = asn1.fromBER(base64.toByteArray(b64).buffer)
    super({schema: asn.result})
  
    this.dn = this.subject.typesAndValues.reduce((dnObj, attrTypeAndValue) => {
      const field = OID[attrTypeAndValue.type] || attrTypeAndValue.type
      dnObj[field] = attrTypeAndValue.value.valueBlock.value
      return dnObj
    }, {})
    this.uid = this.dn.uid
    if (!this.uid || MRN.test(this.uid) !== true) {
      throw CertificateError.SubjectNotMrn(this.dnString)
    }

    const ipidBlock = this.issuer.typesAndValues.find(attrTypeAndValue => attrTypeAndValue.type === OID.uid)
    this.ipid = ipidBlock ? ipidBlock.value.valueBlock.value : undefined

    const extnSubjectAltName = (this.extensions || []).find(extn => extn.extnID === OID.subjectAltName)
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

    const extnAuthKey = (this.extensions || []).find(extn => extn.extnID === OID.authorityKeyIdentifier)
    this.authorityKeyIdentifier = extnAuthKey.parsedValue.keyIdentifier

    const extnBasicConstraints = (this.extensions || []).find(extn => extn.extnID === OID.basicConstraints)
    if (extnBasicConstraints) {
      this.ca = extnBasicConstraints.parsedValue.cA
      this.pathLenConstraint = extnBasicConstraints.parsedValue.pathLenConstraint
    }

    const extnAuthInfoAccess = (this.extensions || []).find(extn => extn.extnID === OID.authorityInfoAccess)
    if (extnAuthInfoAccess) {
      extnAuthInfoAccess.parsedValue.accessDescriptions.forEach(des => {
        const accessMethod = OID[_parseOID(des.accessMethod)]
        if (accessMethod) {
          this[`${accessMethod}Url`] = des.accessLocation.value
        }
      })
    }
  }

  get _cache () {
    return this.constructor._cache
  }

  get dnString () {
    Object.entries(this.dn).map(entry => `${entry[0]}=${entry[1]}`).join(',')
  }

  get serial () {
    return this.serialNumber
  }

  get validFrom () {
    return this.notBefore.value
  }

  get validTo () {
    return this.notAfter.value
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

  get jwk () {
    return this.subjectPublicKeyInfo.toJSON()
  }

  async updateFingerprint (hashAlgorithm = 'SHA-1') {
    const subtle = pki.getEngine().subtle
    try {
      const bytes = await subtle.digest(hashAlgorithm, this.toSchema(true).toBER())
      this.fingerprint = [...new Uint8Array(bytes)].map(byte => byte.toString(16).padStart(2, '0').toUpperCase()).join(':')
    } catch (err) {
      console.error(err)
      throw err
    }
    return this.fingerprint
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

  async checkIssued(issuerCert) {
    // check that this cert was issued and signed by the given issuer
    return await this.verify(issuerCert)
  }

  async validate (uid, issuerCert, options) {
    if (uid && this.uid !== uid) {
      throw CertificateError.UidMismatch(this.uid, uid)
    }

    const now = new Date()
    if (now > this.validTo) {
      throw CertificateError.Expired(this)
    }
    if (now < this.validFrom) {
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

  static async fromPEM (pem, asArray = false) {
    const certificates = []
    const chunks = pem.match(/-----BEGIN CERTIFICATE-----\s([\n\ra-zA-Z0-9/+=]+)-----END CERTIFICATE-----/g)
    chunks.forEach(async chunk => {
      try {
        const cert = new MCPCertificate(chunk)
        certificates.push(cert)
      } catch (err) {
        console.warn(err)
      }
    })
    const promise = Promise.all(certificates.map(cert => cert.updateFingerprint()))
    await promise
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

  static async initialize (options = {spid: 'urn:mrn:mcp:id:aboamare:test:sp'}) {
    Object.assign(this.validationOptions, options)

    if (this.validationOptions.cache) {
      this._initCache()
    }

    await initCrypto()
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
