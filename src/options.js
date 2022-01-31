import cache from './cache.js'

export class Options {
  static defaults = {
    trusted: new Set([]),
    ogtUrl: '',
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

  trust (certificate) {
    this.trusted.add(certificate.fingerprint)
  }

  noLongerTrust (certificate) {
    try {
      this.trusted.delete(certificate.fingerprint)
    } catch (err) {
      console.info(err)
    }
  }
}
