import chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import chaiThings from 'chai-things'

chai.should()
chai.use(chaiThings)
chai.use(chaiAsPromised)
const expect = chai.expect

import { MCPCertificate } from '../src/certificate.js'
import { Options } from '../src/options.js'
import Errors from '../src/errors.js'
const { CertificateError } = Errors

const pemChain = `-----BEGIN CERTIFICATE-----
MIIDzDCCA1GgAwIBAgIGAX6gpxzBMAoGCCqGSM49BAMDMC4xLDAqBgoJkiaJk/Is
ZAEBDBx1cm46bXJuOm1jcDppZDphYm9hbWFyZTp0ZXN0MB4XDTIyMDEyODEyMjY1
M1oXDTI0MDEyOTEyMjY1M1owPjE8MDoGCgmSJomT8ixkAQEMLHVybjptcm46bWNw
OmlkOmFib2FtYXJlOnRlc3Q6YWJvYW1hcmUtc3Bpcml0MHYwEAYHKoZIzj0CAQYF
K4EEACIDYgAE4kB3LISIJ51cf6R9wq4XNe03aXAD6HAQjolYsTHxvuXvdrMcXfud
gbDvnFryoenSLkxAW0bdxUAF5aHzU2Suqw2SJDcWk3SBXIXy3Wp+6pPH3jgwOdKy
zGejqcMnQebmo4ICLDCCAigwgfEGA1UdEQSB6TCB5qA8BgoJkiaJk/IsZAEBoC4M
LHVybjptcm46bWNwOmlkOmFib2FtYXJlOnRlc3Q6YWJvYW1hcmUtc3Bpcml0oCMG
CSqGSIb3DQEJAaAWDBRtaXJAbWlyLmFib2FtYXJlLm5ldKAYBgNVBAOgEQwPQWJv
YU1hcmUgU3Bpcml0oCAGFGmCuYjwwJuv+MfLqb3AgKqu14oboAgMBkFCQ0RFRqAg
BhRpg63i7/fbuZK2yaKN346Qu//uS6AIDAZGSSBUS1WgIwYUaYPuloSAm6/4x8uL
qcCAqq7XihugCwwJMjMwOTk5OTk5MB0GA1UdDgQWBBSYp5y1/7AZI6oinE0VnOTZ
jP5QdTAfBgNVHSMEGDAWgBR7RX0w8WNyQBU3dJQT4mLHMcoubDALBgNVHQ8EBAMC
AIAwGQYDVR0lBBIwEAYEVR0lAAYIKwYBBQUHAwIwMgYDVR0fBCswKTAnoCWgI4Yh
aHR0cHM6Ly9taXIuYWJvYW1hcmUubmV0L3Rlc3QvY3JsMIGVBggrBgEFBQcBAQSB
iDCBhTAuBggrBgEFBQcwAYYiaHR0cHM6Ly9taXIuYWJvYW1hcmUubmV0L3Rlc3Qv
b2NzcDBTBhRpgtPXwdzsqMKCjbaw38HG6v3ZWIY7aHR0cHM6Ly9taXIuYWJvYW1h
cmUubmV0L3Rlc3QvY2VydGlmaWNhdGVzLzAxN2VhMGE3MWNjMS54NXUwCgYIKoZI
zj0EAwMDaQAwZgIxAPCxIviyZ08JA+Vu/57ZiWK29BI+D0YSBDtc/miUQO4ebXnq
K/DM1RWcA9ATRR7M3AIxALDg/eEsEH/8Uc9ne0oBMZQpTFdqvoYIc0/khIT80G9s
JMSVSjPJaio3OTBA2aJvlw==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDejCCAwGgAwIBAgIGAX6gpxx4MAoGCCqGSM49BAMDMCkxJzAlBgoJkiaJk/Is
ZAEBDBd1cm46bXJuOm1jcDppZDphYm9hbWFyZTAeFw0yMjAxMjgxMjI2NTNaFw0y
NDAxMjkxMjI2NTNaMC4xLDAqBgoJkiaJk/IsZAEBDBx1cm46bXJuOm1jcDppZDph
Ym9hbWFyZTp0ZXN0MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEGnRW053Eyv0D08RV
LNDRwutkEH2GaxvYdIRXMympZBnXDWaXTY5kG5aOI2rBRXm7rHAeCHe/oGKQcH3H
7KlZ6nvOvAktc9fl/4SYrkg1aU6D1T6izzJPdMu6vS2KqwOFo4IB8TCCAe0wXQYD
VR0RBFYwVKAjBgkqhkiG9w0BCQGgFgwUbWlyQG1pci5hYm9hbWFyZS5uZXSgCwYD
VQQGoAQMAkZJoBEGA1UECqAKDAhhYm9hbWFyZaANBgNVBAugBgwEdGVzdDAdBgNV
HQ4EFgQUe0V9MPFjckAVN3SUE+JixzHKLmwwHwYDVR0jBBgwFoAU9KQUJQAZG4Pm
FTXhirSBcwGiL9UwCwYDVR0PBAQDAgCEMBMGA1UdJQQMMAoGCCsGAQUFBwMCMBIG
A1UdEwEB/wQIMAYBAf8CAQQwMgYDVR0fBCswKTAnoCWgI4YhaHR0cHM6Ly9taXIu
YWJvYW1hcmUubmV0L3Rlc3QvY3JsMIGVBggrBgEFBQcBAQSBiDCBhTAuBggrBgEF
BQcwAYYiaHR0cHM6Ly9taXIuYWJvYW1hcmUubmV0L3Rlc3Qvb2NzcDBTBhRpgtPX
wdzsqMKCjbaw38HG6v3ZWIY7aHR0cHM6Ly9taXIuYWJvYW1hcmUubmV0L3Rlc3Qv
Y2VydGlmaWNhdGVzLzAxN2VhMGE3MWM3OC54NXUwSgYIKwYBBQUHAQsEPjA8MDoG
FGmBpdbSq6zWgpHpgdHyhtaCi7tJhiJodHRwczovL21pci5hYm9hbWFyZS5uZXQv
dGVzdC9tYXRwMAoGCCqGSM49BAMDA2cAMGQCMF6bmu4N7vLY04xiGILoNRLcaUx9
zoc+uQILTqap2Wmi8sRgZ1KlvZLq5APAeAk+sAIwOWjcec8+afamZzmr9mkbAfWJ
9Z+s68zzOn/ChSBqDTTMdzPTttUwouW7jlGkFBdO
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIID1DCCA1qgAwIBAgIGAX6gpwASMAoGCCqGSM49BAMDMEExPzAPBgNVBAoMCGFi
b2FtYXJlMAkGA1UEBgwCRkkwIQYJKoZIhvcNAQkBDBRtaXJAbWlyLmFib2FtYXJl
Lm5ldDAeFw0yMjAxMjgxMjI2NDZaFw0yNzAxMjgxMjI2NDZaMCkxJzAlBgoJkiaJ
k/IsZAEBDBd1cm46bXJuOm1jcDppZDphYm9hbWFyZTB2MBAGByqGSM49AgEGBSuB
BAAiA2IABCx4M8kA534iLkngeUouo2v7ndSs6KHjk7glVhHC6HDD+EvtsxZujuBy
YJUwAKRDhSd8PlsJZjvroMkuPh+NJxTyyVM648wQ0MCf/b2CQyk7PTsyPSC1Ia0v
C3gHALCJ/qOCAjcwggIzMIGSBgNVHREEgYowgYegIwYJKoZIhvcNAQkBoBYMFG1p
ckBtaXIuYWJvYW1hcmUubmV0oAsGA1UEBqAEDAJGSaARBgNVBAqgCgwIYWJvYW1h
cmWgQAYUaYLw3/a3q7CKms+l3pTU+NPS5V+gKAwmaHR0cHM6Ly9taXIuYWJvYW1h
cmUubmV0L2Fib2FtYXJlLmh0bWwwHQYDVR0OBBYEFPSkFCUAGRuD5hU14Yq0gXMB
oi/VMB8GA1UdIwQYMBaAFPBeiaiKNbrPN3FmooKZbnjlJdJOMAsGA1UdDwQEAwIA
hDATBgNVHSUEDDAKBggrBgEFBQcDAjASBgNVHRMBAf8ECDAGAQH/AgEEMDYGA1Ud
HwQvMC0wK6ApoCeGJWh0dHBzOi8vbWlyLmFib2FtYXJlLm5ldC9hYm9hbWFyZS9j
cmwwgZ0GCCsGAQUFBwEBBIGQMIGNMDIGCCsGAQUFBzABhiZodHRwczovL21pci5h
Ym9hbWFyZS5uZXQvYWJvYW1hcmUvb2NzcDBXBhRpgtPXwdzsqMKCjbaw38HG6v3Z
WIY/aHR0cHM6Ly9taXIuYWJvYW1hcmUubmV0L2Fib2FtYXJlL2NlcnRpZmljYXRl
cy8wMTdlYTBhNzAwMTIueDV1ME4GCCsGAQUFBwELBEIwQDA+BhRpgaXW0qus1oKR
6YHR8obWgou7SYYmaHR0cHM6Ly9taXIuYWJvYW1hcmUubmV0L2Fib2FtYXJlL21h
dHAwCgYIKoZIzj0EAwMDaAAwZQIwSlpM5vc0WHNDp1DT6mwvVShPun1tPprlpwgv
1tsOhoaKaNbsV83nrCAuPFK+mbNFAjEAiUvZAnTBtLxQRFbwemeJqWYd/EMmhCkY
4E8U9crL+ZJBKaZ5PYTBkg05PVSjWlRw
-----END CERTIFICATE-----`

describe('Certificates', function () {

  let validationOptions

  before(async function () {
    await MCPCertificate.initialize()
    validationOptions = new Options({spid: 'urn:mrn:mcp:id:aboamare:test:sp'})
  })

  it('import chain from PEM', async function () {
    const chain = await MCPCertificate.fromPEM(pemChain, true)
    chain.should.be.an('array')
    chain.should.have.lengthOf(3)
    chain.should.all.be.instanceOf(MCPCertificate)

    let cert = chain[0]
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

    cert = chain[1]
    cert.should.have.property('uid')
    cert.uid.should.equal('urn:mrn:mcp:id:aboamare:test')
    cert.should.have.property('ipid')
    cert.ipid.should.equal('urn:mrn:mcp:id:aboamare')
    cert.validTo.should.be.instanceOf(Date)
    cert.x5uUrl.should.be.a('string')
    cert.matpUrl.should.be.a('string')
  
  })

  it('validate chain without trust in anchor', async function () {
    const chain = await MCPCertificate.fromPEM(pemChain, true)
    const validate = MCPCertificate.validate(chain, 'urn:mrn:mcp:id:aboamare:test:aboamare-spirit', validationOptions)
    validate.should.be.rejectedWith(CertificateError)
  })

  it('validate chain with trust in anchor', async function () {
    const chain = await MCPCertificate.fromPEM(pemChain, true)
    validationOptions.trust(chain[2])
    let validate = MCPCertificate.validate(chain, 'urn:mrn:mcp:id:aboamare:test:aboamare-spirit', validationOptions)
    validate.should.not.be.rejectedWith(CertificateError)
    
    validationOptions.noLongerTrust(chain[2])
    validate = MCPCertificate.validate(chain, 'urn:mrn:mcp:id:aboamare:test:aboamare-spirit', validationOptions)
    validate.should.be.rejectedWith(CertificateError)
  })

})