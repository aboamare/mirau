import pki  from 'pkijs' 
import asn1 from 'asn1js'
import base64 from 'base64-js'

import { MRN } from  './mrn.js'
import { OID }  from './mcp-oids.js'
import OCSP from './ocsp.js'
import { Options } from './options.js'
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

function bufToHex(buffer) { // buffer is an ArrayBuffer
  return [...new Uint8Array(buffer)]
      .map(x => x.toString(16).padStart(2, '0'))
      .join('');
}

export async function initCrypto() {
  const engine = pki.getEngine()
  if (!engine.subtle) {
    try {
      const nodeCrypto = await import('crypto')
      const crypto = new pki.CryptoEngine({name: "node", crypto: nodeCrypto.webcrypto, subtle: nodeCrypto.webcrypto.subtle})
      pki.setEngine("node", nodeCrypto.webcrypto, crypto)
    } catch (err) {
      throw Error('Crypto engine support is not available')
    }
  }
}

export class MCPCertificate extends pki.Certificate {
  constructor (pem) {
    if (!pem) {
      super()
      return
    }
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

    const extnSubjectInfoAccess = (this.extensions || []).find(extn => extn.extnID === OID.subjectInfoAccess)
    if (extnSubjectInfoAccess) {
      extnSubjectInfoAccess.parsedValue.accessDescriptions.forEach(des => {
        const accessMethod = OID[_parseOID(des.accessMethod)]
        if (accessMethod) {
          this[`${accessMethod}Url`] = des.accessLocation.value
        }
      })
    }
  }

  get dnString () {
    Object.entries(this.dn).map(entry => `${entry[0]}=${entry[1]}`).join(',')
  }

  get serial () {
    return bufToHex(this.serialNumber.valueBlock.valueHex)
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

  cacheAs (cache, status = 'good', kind) {
    if (!cache) {
      return
    }
    if (kind === undefined && status === 'trusted') {
      kind = 'trusted'
    } else if (kind === undefined && this.ca) {
      kind = 'mir'
    } else {
      kind = 'certificate'
    }
    const expireIn = cache.expireIn[kind]
    const expires = typeof expireIn === 'function' ? expireIn() : undefined
    cache.set(this.fingerprint, status, expires)
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
    if (options.cache) {
      result = options.cache.get(this.fingerprint)
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
    if (options.cache && options.trusted.has(this.fingerprint)) {
      this.cacheAs(options.cache, 'trusted')
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
    } else if (!issuerCert && !(options.allowUnknownMir && this.ca && MRN.test(this.uid))) {
      throw CertificateError.UnknownStatus(this)
    }

    if (issuerCert && !issuerCert.ca) {
      throw CertificateError.IssuerNotCA(issuerCert)
    }
    if (issuerCert && !this.checkIssued(issuerCert)) {
      throw CertificateError.NotIssued(this, issuerCert)
    }

    if (!issuerCert) {
      // this cert is not trusted but... 
      if (options.allowUnknownMir && this.ca && MRN.test(this.uid)) {
        // we allow unknown MIRs. This is useful when checking attestations, and e.g. in testing
        return
      }
      if (options.trustAttested) {
        //TODO: do the OGT-2 dance
      }

      throw CertificateError.NotTrusted(this)
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

  static async initialize () {
    await initCrypto()
  }

  static async validate (chain, uid, options = {}) {
    const validationOptions = options instanceof Options ? options : new Options(options)
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
  }
}

Object.assign(MCPCertificate, CertificateError.Codes)