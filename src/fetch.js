import fetch from 'isomorphic-unfetch'

let rewriteRules = new Map()

function rewrite(url) {
  let rewritten = undefined
  for (const [regex, replacement] of rewriteRules.values()) {
    if (regex.test(url)) {
      rewritten = url.replace(regex, replacement)
      break
    }
  }
  return rewritten || url
}

function Fetch (url, options) {
  return fetch(rewrite(url), options)
}

Fetch.addRule = function (pattern, replacement) {
  const regex = pattern instanceof RegExp ? pattern : new RegExp(`^${pattern}`)
  rewriteRules.set(pattern, [regex, replacement])
}

Fetch.removeRules = function (pattern) {
  const filteredRules = Array.from(rewriteRules.entries()).filter(([p, [re, rep]]) => re.test(pattern) !== true)
  rewriteRules = new Map(filteredRules)
}

export default Fetch