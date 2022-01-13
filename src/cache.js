import dayjs from 'dayjs'

export class Cache extends Map {
  constructor (options = {}) {
    super()
    this._options = Object.assign({}, Cache.defaults, options)
    if (typeof this._options.expireIn === 'string') {
      this._options.expireIn = this.expireIn(this._options.expireIn)
    }
  }

  expireIn (periodString = '30 minutes') {
    const args = periodString.split(/\s/)
    args[0] = parseInt(args[0])
    return function () {
      return dayjs().add(...args).toDate() 
    }      
  }

  get maxEntries () {
    return this._options.maxEntries
  }

  get (key) {
    const entry = super.get(key)
    if (!entry) {
      return undefined
    }
    const now = dayjs().valueOf()
    if (now > entry.expires) {
      this.delete(key)
      return undefined
    }
    return entry.value
  }

  set (key, value, expires) {
    const entry = { value }
    entry.expires = (expires || value.expires || this._options.expireIn()).valueOf()
    super.set(key, entry)
    if (this.size > this.maxEntries) {
      this.purge()
    }
    return value
  }

  purge (space = 0) {
    const now = dayjs()
    const sorted = [...this.entries()].sort((a, b) => a[1].expires - b[1].expires)
    if (sorted.length < 1) {
      return
    }
    const limit = this._options.maxEntries - (space || Math.floor(this._options.maxEntries * 0.9))
    while (sorted.length > limit) {
      const [key, entry] = sorted.shift()
      this.delete(key)
    }
    let next = sorted.shift()
    while (next) {
      const [key, entry] = next
      if (now > entry.expires) {
        this.delete(key)
        next = sorted.shift()
      } else {
        next = false
      }
    }
  }

  static defaults = {
    maxEntries: 1000,
    expireIn: '48 hours'
  }
}

export default { Cache }