import { expect } from 'chai'
import Errors from '../src/errors.js'

const { JwtError } = Errors

describe('Errors', function () {
  it('JwtError', function () {
    function throwError () {
      throw JwtError.InvalidNonce({}, 'nononce')
    }
    expect(JwtError.InvalidNonce).to.be.a('function')
    const err = JwtError.InvalidNonce({}, 'nononce')
    expect(err.code).to.equal(JwtError.Codes.InvalidNonce)
    expect(throwError).to.throw()
  })
})