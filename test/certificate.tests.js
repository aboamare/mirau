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
MIIDSzCCAtGgAwIBAgIGAX5jpIs5MAoGCCqGSM49BAMDMC4xLDAqBgoJkiaJk/Is
ZAEBDBx1cm46bXJuOm1jcDppZDphYm9hbWFyZTp0ZXN0MB4XDTIyMDExNjE2MDcx
NVoXDTI0MDExNzE2MDcxNVowPjE8MDoGCgmSJomT8ixkAQEMLHVybjptcm46bWNw
OmlkOmFib2FtYXJlOnRlc3Q6YWJvYW1hcmUtc3Bpcml0MHYwEAYHKoZIzj0CAQYF
K4EEACIDYgAENR1g4V6Q2OOGT5nzgys6iVF8ijcmm7XW4r7zicwSfXaaA7PDekOO
EVjeoq6SGJ5lredpwLEmJgOuAJ7drXQblBCBXzMiX+n3sHH7P/9QeP4u4+y87nGC
l5EGcDhIqMoPo4IBrDCCAagwcgYDVR0RBGswaaAgBhRpgrmI8MCbr/jHy6m9wICq
rteKG6AIDAZBQkNERUagIwYUaYPuloSAm6/4x8uLqcCAqq7XihugCwwJMjMwOTk5
OTk5oCAGFGmDreLv99u5krbJoo3fjpC7/+5LoAgMBkZJIFRLVTAdBgNVHQ4EFgQU
p8VMbYqWwowvusyGGw1xswy55IQwHwYDVR0jBBgwFoAUdlZaVnAvzpKA7gA4vEnf
jkqZByEwCwYDVR0PBAQDAgCAMBkGA1UdJQQSMBAGBFUdJQAGCCsGAQUFBwMCMDIG
A1UdHwQrMCkwJ6AloCOGIWh0dHBzOi8vbWlyLmFib2FtYXJlLm5ldC90ZXN0L2Ny
bDCBlQYIKwYBBQUHAQEEgYgwgYUwLgYIKwYBBQUHMAGGImh0dHBzOi8vbWlyLmFi
b2FtYXJlLm5ldC90ZXN0L29jc3AwUwYUaYLT18Hc7KjCgo22sN/Bxur92ViGO2h0
dHBzOi8vbWlyLmFib2FtYXJlLm5ldC90ZXN0L2NlcnRpZmljYXRlcy8wMTdlNjNh
NDhiMzkueDV1MAoGCCqGSM49BAMDA2gAMGUCMCfT7nCJ9g42s7gcrQp8fp5CeA+9
7h9P99NLbIH0KC83C0QrdSC9VkgO64Kt1dcTIAIxAM+JKI3trpyNKq8o2JNZaKHZ
zwg0Nj1fRnOfy36mz4k7Ssh5wklTRQKjy39qCrWzTw==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDSDCCAs2gAwIBAgIGAX5jpIsWMAoGCCqGSM49BAMDMCkxJzAlBgoJkiaJk/Is
ZAEBDBd1cm46bXJuOm1jcDppZDphYm9hbWFyZTAeFw0yMjAxMTYxNjA3MTRaFw0y
NDAxMTcxNjA3MTRaMC4xLDAqBgoJkiaJk/IsZAEBDBx1cm46bXJuOm1jcDppZDph
Ym9hbWFyZTp0ZXN0MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEBL+z7GgTuqP+11Wi
co2gwL+LiKDydKRQHmJMAdtha/5EXdd3epnCqj10hY+/HL/cn+6cPAXXMXOLR7jw
kBksHtyOKTJs0i/IdArSR/63fp17C5OcKgGjNGFWOo2vMGyVo4IBvTCCAbkwKQYD
VR0RBCIwIKARBgNVBAqgCgwIYWJvYW1hcmWgCwYDVQQGoAQMAkZJMB0GA1UdDgQW
BBR2VlpWcC/OkoDuADi8Sd+OSpkHITAfBgNVHSMEGDAWgBSkNTKkXyW1SpiHEfq3
fx2qFPB9qTALBgNVHQ8EBAMCAIQwEwYDVR0lBAwwCgYIKwYBBQUHAwIwEgYDVR0T
AQH/BAgwBgEB/wIBBDAyBgNVHR8EKzApMCegJaAjhiFodHRwczovL21pci5hYm9h
bWFyZS5uZXQvdGVzdC9jcmwwgZUGCCsGAQUFBwEBBIGIMIGFMC4GCCsGAQUFBzAB
hiJodHRwczovL21pci5hYm9hbWFyZS5uZXQvdGVzdC9vY3NwMFMGFGmC09fB3Oyo
woKNtrDfwcbq/dlYhjtodHRwczovL21pci5hYm9hbWFyZS5uZXQvdGVzdC9jZXJ0
aWZpY2F0ZXMvMDE3ZTYzYTQ4YjE2Lng1dTBKBggrBgEFBQcBCwQ+MDwwOgYUaYGl
1tKrrNaCkemB0fKG1oKLu0mGImh0dHBzOi8vbWlyLmFib2FtYXJlLm5ldC90ZXN0
L2FhdHAwCgYIKoZIzj0EAwMDaQAwZgIxAIEwjyAT88lWZwCzoJVJolwduIY5HUlS
YcchVk7WvzBg39tTClCdS+guYHssGtgDsAIxAI+ZC8MC7AhEh/1/qTW2HmnLDBeL
fvYWHLkT09FEX9yy/qQ8J6/iTmMz175JST7g+A==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDaTCCAvCgAwIBAgIGAX5jo7X6MAoGCCqGSM49BAMDMEExPzAPBgNVBAoMCGFi
b2FtYXJlMAkGA1UEBgwCRkkwIQYJKoZIhvcNAQkBDBRtaXJAbWlyLmFib2FtYXJl
Lm5ldDAeFw0yMjAxMTYxNjA2MjBaFw0yNzAxMTYxNjA2MjBaMCkxJzAlBgoJkiaJ
k/IsZAEBDBd1cm46bXJuOm1jcDppZDphYm9hbWFyZTB2MBAGByqGSM49AgEGBSuB
BAAiA2IABBzirW9/lnoL9XSYimWx4jSD8fsL745jgPbuTOtPFtNULzt7NwXm37iR
aa417/MGqXWVwDw0KBYH3dfzDyPpJv16eVrKmvxElwaHcgGnVjMiIHdnEdedL947
EUoFas2JNKOCAc0wggHJMCkGA1UdEQQiMCCgEQYDVQQKoAoMCGFib2FtYXJloAsG
A1UEBqAEDAJGSTAdBgNVHQ4EFgQUpDUypF8ltUqYhxH6t38dqhTwfakwHwYDVR0j
BBgwFoAU9/hmS+4hgcZOvWEb4vnt3YJuiNswCwYDVR0PBAQDAgCEMBMGA1UdJQQM
MAoGCCsGAQUFBwMCMBIGA1UdEwEB/wQIMAYBAf8CAQQwNgYDVR0fBC8wLTAroCmg
J4YlaHR0cHM6Ly9taXIuYWJvYW1hcmUubmV0L2Fib2FtYXJlL2NybDCBnQYIKwYB
BQUHAQEEgZAwgY0wMgYIKwYBBQUHMAGGJmh0dHBzOi8vbWlyLmFib2FtYXJlLm5l
dC9hYm9hbWFyZS9vY3NwMFcGFGmC09fB3OyowoKNtrDfwcbq/dlYhj9odHRwczov
L21pci5hYm9hbWFyZS5uZXQvYWJvYW1hcmUvY2VydGlmaWNhdGVzLzAxN2U2M2Ez
YjVmYS54NXUwTgYIKwYBBQUHAQsEQjBAMD4GFGmBpdbSq6zWgpHpgdHyhtaCi7tJ
hiZodHRwczovL21pci5hYm9hbWFyZS5uZXQvYWJvYW1hcmUvYWF0cDAKBggqhkjO
PQQDAwNnADBkAjBm1g3wWqFiDvDyz1nSAOD1xHQ7p/ON6rtN9hjgHf7eyshWIl5n
d42GyXkqipw3nRYCMAPCK/Pa3mMtW7qB3i6h19fP846cSdNrOVgo84qwTmBAHVtO
fsAyUQZHO7vshfPi1g==
-----END CERTIFICATE-----`

describe('Certificates', function () {

  before(function () {
    MCPCertificate.initialize()
  })

  it('import chain from PEM', function () {
    const chain = MCPCertificate.fromPEM(pemChain, true)
    chain.should.be.an('array')
    chain.should.have.lengthOf(3)
    chain.should.all.be.instanceOf(MCPCertificate)

    const cert = chain[0]
    cert.should.have.property('uid')
    cert.uid.should.equal('urn:mrn:mcp:id:aboamare:test:aboamare-spirit')
    cert.should.have.property('ipid')
    cert.ipid.should.equal('urn:mrn:mcp:id:aboamare:test')
    cert.validTo.should.be.a('string')
    cert.x5uUrl.should.be.a('string')
    cert.callSign.should.be.a('string')
    cert.MMSI.should.be.a('string')
    cert.homePort.should.be.a('string')
    expect(cert.serial, 'cert should have serial').to.exist
  })

  it('validate chain without trust in anchor', async function () {
    const chain = MCPCertificate.fromPEM(pemChain, true)
    const validate = MCPCertificate.validate(chain, 'urn:mrn:mcp:id:aboamare:test:aboamare-spirit', {spid: 'urn:mrn:mcp:id:aboamare:test:sp'})
    validate.should.be.rejectedWith(CertificateError)
  })

  it('validate chain with trust in anchor', async function () {
    const chain = MCPCertificate.fromPEM(pemChain, true)
    MCPCertificate.trust(chain[2])
    let validate = MCPCertificate.validate(chain, 'urn:mrn:mcp:id:aboamare:test:aboamare-spirit', {spid: 'urn:mrn:mcp:id:aboamare:test:sp'})
    validate.should.not.be.rejectedWith(CertificateError)
    
    MCPCertificate.noLongerTrust(chain[2])
    validate = MCPCertificate.validate(chain, 'urn:mrn:mcp:id:aboamare:test:aboamare-spirit', {spid: 'urn:mrn:mcp:id:aboamare:test:sp'})
    validate.should.be.rejectedWith(CertificateError)
  })

})