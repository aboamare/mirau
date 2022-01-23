import chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import chaiThings from 'chai-things'

chai.should()
chai.use(chaiThings)
chai.use(chaiAsPromised)
const expect = chai.expect

import { MCPCertificate } from '../src/certificate.js'
import Errors from '../src/errors.js'
const { CertificateError } = Errors

const pemChain = `-----BEGIN CERTIFICATE-----
MIIDyjCCA1GgAwIBAgIGAX5zL253MAoGCCqGSM49BAMDMC4xLDAqBgoJkiaJk/Is
ZAEBDBx1cm46bXJuOm1jcDppZDphYm9hbWFyZTp0ZXN0MB4XDTIyMDExOTE2MzMx
NVoXDTI0MDEyMDE2MzMxNVowPjE8MDoGCgmSJomT8ixkAQEMLHVybjptcm46bWNw
OmlkOmFib2FtYXJlOnRlc3Q6YWJvYW1hcmUtc3Bpcml0MHYwEAYHKoZIzj0CAQYF
K4EEACIDYgAE4kB3LISIJ51cf6R9wq4XNe03aXAD6HAQjolYsTHxvuXvdrMcXfud
gbDvnFryoenSLkxAW0bdxUAF5aHzU2Suqw2SJDcWk3SBXIXy3Wp+6pPH3jgwOdKy
zGejqcMnQebmo4ICLDCCAigwgfEGA1UdEQSB6TCB5qA8BgoJkiaJk/IsZAEBoC4M
LHVybjptcm46bWNwOmlkOmFib2FtYXJlOnRlc3Q6YWJvYW1hcmUtc3Bpcml0oCMG
CSqGSIb3DQEJAaAWDBRtaXJAbWlyLmFib2FtYXJlLm5ldKAYBgNVBAOgEQwPQWJv
YU1hcmUgU3Bpcml0oCAGFGmCuYjwwJuv+MfLqb3AgKqu14oboAgMBkFCQ0RFRqAg
BhRpg63i7/fbuZK2yaKN346Qu//uS6AIDAZGSSBUS1WgIwYUaYPuloSAm6/4x8uL
qcCAqq7XihugCwwJMjMwOTk5OTk5MB0GA1UdDgQWBBSYp5y1/7AZI6oinE0VnOTZ
jP5QdTAfBgNVHSMEGDAWgBTWsyCvcxlQU6WWDOI9aa0AbF8MEzALBgNVHQ8EBAMC
AIAwGQYDVR0lBBIwEAYEVR0lAAYIKwYBBQUHAwIwMgYDVR0fBCswKTAnoCWgI4Yh
aHR0cHM6Ly9taXIuYWJvYW1hcmUubmV0L3Rlc3QvY3JsMIGVBggrBgEFBQcBAQSB
iDCBhTAuBggrBgEFBQcwAYYiaHR0cHM6Ly9taXIuYWJvYW1hcmUubmV0L3Rlc3Qv
b2NzcDBTBhRpgtPXwdzsqMKCjbaw38HG6v3ZWIY7aHR0cHM6Ly9taXIuYWJvYW1h
cmUubmV0L3Rlc3QvY2VydGlmaWNhdGVzLzAxN2U3MzJmNmU3Ny54NXUwCgYIKoZI
zj0EAwMDZwAwZAIwFyNCx2fYX+r/2/LRQJE3AIEH7AHPRpuhiNIbdnkd46ZT5RMa
prFliLcBrDYDH1s9AjAqwXFECkUIkZvqrOA81IEG4/fTdEl/0HA3GDqrriLFAW7e
KPOIJ3HvSJ+Taneyp5Q=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDejCCAwGgAwIBAgIGAX5zL25PMAoGCCqGSM49BAMDMCkxJzAlBgoJkiaJk/Is
ZAEBDBd1cm46bXJuOm1jcDppZDphYm9hbWFyZTAeFw0yMjAxMTkxNjMzMTVaFw0y
NDAxMjAxNjMzMTVaMC4xLDAqBgoJkiaJk/IsZAEBDBx1cm46bXJuOm1jcDppZDph
Ym9hbWFyZTp0ZXN0MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEA9vZa15qfT70iPqf
S7U8anaz1xToMfQvRSv+el/VC9vEXaw29T6nVZ5ZNUrgS9mRs4ekHSRn/n8wpzC0
//oFqcnUtx09pod2rfXBulvzIMvlLnSkWheuGbamOShoXL7to4IB8TCCAe0wXQYD
VR0RBFYwVKAjBgkqhkiG9w0BCQGgFgwUbWlyQG1pci5hYm9hbWFyZS5uZXSgCwYD
VQQGoAQMAkZJoBEGA1UECqAKDAhhYm9hbWFyZaANBgNVBAugBgwEdGVzdDAdBgNV
HQ4EFgQU1rMgr3MZUFOllgziPWmtAGxfDBMwHwYDVR0jBBgwFoAU1dKG4kdMarb4
zakcTcm0rLm9woIwCwYDVR0PBAQDAgCEMBMGA1UdJQQMMAoGCCsGAQUFBwMCMBIG
A1UdEwEB/wQIMAYBAf8CAQQwMgYDVR0fBCswKTAnoCWgI4YhaHR0cHM6Ly9taXIu
YWJvYW1hcmUubmV0L3Rlc3QvY3JsMIGVBggrBgEFBQcBAQSBiDCBhTAuBggrBgEF
BQcwAYYiaHR0cHM6Ly9taXIuYWJvYW1hcmUubmV0L3Rlc3Qvb2NzcDBTBhRpgtPX
wdzsqMKCjbaw38HG6v3ZWIY7aHR0cHM6Ly9taXIuYWJvYW1hcmUubmV0L3Rlc3Qv
Y2VydGlmaWNhdGVzLzAxN2U3MzJmNmU0Zi54NXUwSgYIKwYBBQUHAQsEPjA8MDoG
FGmBpdbSq6zWgpHpgdHyhtaCi7tJhiJodHRwczovL21pci5hYm9hbWFyZS5uZXQv
dGVzdC9tYXRwMAoGCCqGSM49BAMDA2cAMGQCMBrMZdJ5topBqyw/SQOT7nqB6/Eo
gtL6twW2pZFIKvdmM3F0SHrLZFj6W0A7ma9J1gIwMKohkdZ8b3fOqFL28Ouumgng
8AvKMgttbySQ32HiRVlHN32Tp+t/nxbmdTeSgZQl
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIID0zCCA1qgAwIBAgIGAX5zL1q3MAoGCCqGSM49BAMDMEExPzAPBgNVBAoMCGFi
b2FtYXJlMAkGA1UEBgwCRkkwIQYJKoZIhvcNAQkBDBRtaXJAbWlyLmFib2FtYXJl
Lm5ldDAeFw0yMjAxMTkxNjMzMTBaFw0yNzAxMTkxNjMzMTBaMCkxJzAlBgoJkiaJ
k/IsZAEBDBd1cm46bXJuOm1jcDppZDphYm9hbWFyZTB2MBAGByqGSM49AgEGBSuB
BAAiA2IABKWRu0bmhXePALCsce2cppnxQKnxVzjRkgTaDPQmWNLS0pU+pYCjvssa
WW2OYHa8YI7RfLAoPafHL55177Nkf3Qy45A0CLfRPKv5bREqiXOBY4wwQ13WDNYI
4e9niikTUaOCAjcwggIzMIGSBgNVHREEgYowgYegIwYJKoZIhvcNAQkBoBYMFG1p
ckBtaXIuYWJvYW1hcmUubmV0oAsGA1UEBqAEDAJGSaARBgNVBAqgCgwIYWJvYW1h
cmWgQAYUaYLw3/a3q7CKms+l3pTU+NPS5V+gKAwmaHR0cHM6Ly9taXIuYWJvYW1h
cmUubmV0L2Fib2FtYXJlLmh0bWwwHQYDVR0OBBYEFNXShuJHTGq2+M2pHE3JtKy5
vcKCMB8GA1UdIwQYMBaAFMPdJNliGQPd+0VZWntOvtKCdc2OMAsGA1UdDwQEAwIA
hDATBgNVHSUEDDAKBggrBgEFBQcDAjASBgNVHRMBAf8ECDAGAQH/AgEEMDYGA1Ud
HwQvMC0wK6ApoCeGJWh0dHBzOi8vbWlyLmFib2FtYXJlLm5ldC9hYm9hbWFyZS9j
cmwwgZ0GCCsGAQUFBwEBBIGQMIGNMDIGCCsGAQUFBzABhiZodHRwczovL21pci5h
Ym9hbWFyZS5uZXQvYWJvYW1hcmUvb2NzcDBXBhRpgtPXwdzsqMKCjbaw38HG6v3Z
WIY/aHR0cHM6Ly9taXIuYWJvYW1hcmUubmV0L2Fib2FtYXJlL2NlcnRpZmljYXRl
cy8wMTdlNzMyZjVhYjcueDV1ME4GCCsGAQUFBwELBEIwQDA+BhRpgaXW0qus1oKR
6YHR8obWgou7SYYmaHR0cHM6Ly9taXIuYWJvYW1hcmUubmV0L2Fib2FtYXJlL21h
dHAwCgYIKoZIzj0EAwMDZwAwZAIwY7c75r/BlRjBqpCWz7CCoZ6uwFDDN3BhtQSZ
95M8CnN9011uy3kwEuAnaN9ympedAjBHpJ7qHht3MO7+YLaaJN9JrGl1iTAZiu2x
K7mTKjgtseDENNINdW4RIH3ciq2NYes=
-----END CERTIFICATE-----`

describe('Certificates', function () {

  before(async function () {
    await MCPCertificate.initialize()
  })

  it('import chain from PEM', async function () {
    const chain = await MCPCertificate.fromPEM(pemChain, true)
    chain.should.be.an('array')
    chain.should.have.lengthOf(3)
    chain.should.all.be.instanceOf(MCPCertificate)

    const cert = chain[0]
    cert.should.have.property('uid')
    cert.uid.should.equal('urn:mrn:mcp:id:aboamare:test:aboamare-spirit')
    cert.should.have.property('ipid')
    cert.ipid.should.equal('urn:mrn:mcp:id:aboamare:test')
    cert.validTo.should.be.instanceOf(Date)
    cert.x5uUrl.should.be.a('string')
    cert.callSign.should.be.a('string')
    cert.mmsi.should.be.a('string')
    cert.homePort.should.be.a('string')
    expect(cert.serial, 'cert should have serial').to.exist
  })

  it('validate chain without trust in anchor', async function () {
    const chain = await MCPCertificate.fromPEM(pemChain, true)
    const validate = MCPCertificate.validate(chain, 'urn:mrn:mcp:id:aboamare:test:aboamare-spirit', {spid: 'urn:mrn:mcp:id:aboamare:test:sp'})
    validate.should.be.rejectedWith(CertificateError)
  })

  it('validate chain with trust in anchor', async function () {
    const chain = await MCPCertificate.fromPEM(pemChain, true)
    MCPCertificate.trust(chain[2])
    let validate = MCPCertificate.validate(chain, 'urn:mrn:mcp:id:aboamare:test:aboamare-spirit', {spid: 'urn:mrn:mcp:id:aboamare:test:sp'})
    validate.should.not.be.rejectedWith(CertificateError)
    
    MCPCertificate.noLongerTrust(chain[2])
    validate = MCPCertificate.validate(chain, 'urn:mrn:mcp:id:aboamare:test:aboamare-spirit', {spid: 'urn:mrn:mcp:id:aboamare:test:sp'})
    validate.should.be.rejectedWith(CertificateError)
  })

})