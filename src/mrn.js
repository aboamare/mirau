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