import cache from './cache.js'

export class Options {
  static defaults = {
    trusted: new Map(),
    cache: {
      certificate: '12 hours',
      mir: '48 hours',
      trusted: '48 hours',
      cls: 'Cache'
    },
    jwt: {
      algorithms: ['ES384', 'ES256'],
      clockTolerance: '30 seconds',
      maxTokenAge: '5 minutes'
    },
    strict: true,
    trustedAttestations: ['mirEndorsed', 'mirOk'],
    trustAttested: true
  }

  constructor (options = {spid: 'urn:mrn:mcp:id:aboamare:test:sp'}) {
    Object.assign(this, this.constructor.defaults, options)
    this._initCache()
  }

  _initCache() {
    const cacheOptions = this.cache || false
    if (!cacheOptions) {
      return
    }

    const clsName = cacheOptions.cls || 'Cache'
    const myCache = new cache[clsName]()
    if (!cacheOptions.expireIn) {
      const expireIn = {}
      for (const kind in cacheOptions) {
        if (kind === 'cls') {
          continue
        } else if (typeof cacheOptions[kind] === 'string') {
          expireIn[kind] = myCache.expireIn(cacheOptions[kind])
        } else if (typeof cacheOptions[kind] === 'function') {
          expireIn[kind] = cacheOptions[kind]
        }
      }
      myCache.expireIn = expireIn
    }
    this.cache = myCache
  }

  allowOldTokens () {
    delete this.jwt.clockTolerance
    delete this.jwt.maxTokenAge
  }

  isTrusted (x5t256OrUid) {
    if (this.trusted.has(x5t256OrUid)) {
      return true
    }
    for (const oid of this.trusted.values()) {
      if (oid === x5t256OrUid) {
        return true
      }
    }
    return false
  }

  trust (certificate) {
    this.trusted.set(certificate.fingerprint, certificate.uid)
  }

  noLongerTrust (certificate) {
    try {
      this.trusted.delete(certificate.fingerprint)
    } catch (err) {
      console.info(err)
    }
  }
}
