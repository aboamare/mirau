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
MIIDTDCCAtGgAwIBAgIGAX5TUU3iMAoGCCqGSM49BAMDMC4xLDAqBgoJkiaJk/Is
ZAEBDBx1cm46bXJuOm1jcDppZDphYm9hbWFyZTp0ZXN0MB4XDTIyMDExMzEyMDIy
NFoXDTI0MDExNDEyMDIyNFowPjE8MDoGCgmSJomT8ixkAQEMLHVybjptcm46bWNw
OmlkOmFib2FtYXJlOnRlc3Q6YWJvYW1hcmUtc3Bpcml0MHYwEAYHKoZIzj0CAQYF
K4EEACIDYgAENR1g4V6Q2OOGT5nzgys6iVF8ijcmm7XW4r7zicwSfXaaA7PDekOO
EVjeoq6SGJ5lredpwLEmJgOuAJ7drXQblBCBXzMiX+n3sHH7P/9QeP4u4+y87nGC
l5EGcDhIqMoPo4IBrDCCAagwcgYDVR0RBGswaaAgBhRpgrmI8MCbr/jHy6m9wICq
rteKG6AIDAZBQkNERUagIwYUaYPuloSAm6/4x8uLqcCAqq7XihugCwwJMjMwOTk5
OTk5oCAGFGmDreLv99u5krbJoo3fjpC7/+5LoAgMBkZJIFRLVTAdBgNVHQ4EFgQU
p8VMbYqWwowvusyGGw1xswy55IQwHwYDVR0jBBgwFoAUfX8Jd9eR22p/Je46i6Kj
cOKIviAwCwYDVR0PBAQDAgCAMBkGA1UdJQQSMBAGBFUdJQAGCCsGAQUFBwMCMDIG
A1UdHwQrMCkwJ6AloCOGIWh0dHBzOi8vbWlyLmFib2FtYXJlLm5ldC90ZXN0L2Ny
bDCBlQYIKwYBBQUHAQEEgYgwgYUwLgYIKwYBBQUHMAGGImh0dHBzOi8vbWlyLmFi
b2FtYXJlLm5ldC90ZXN0L29jc3AwUwYUaYLT18Hc7KjCgo22sN/Bxur92ViGO2h0
dHBzOi8vbWlyLmFib2FtYXJlLm5ldC90ZXN0L2NlcnRpZmljYXRlcy8wMTdlNTM1
MTRkZTIueDV1MAoGCCqGSM49BAMDA2kAMGYCMQDvk8dR93BhqN/gVKvalaIAfe0R
6kDhjRhDQd8vXTjtED3THpXfhUoLuvE77BjvrWMCMQCZRWp4EA4cAavVyZckLKME
+tyHqQg0LwUvi9WiqMNwatRQt/1cfU0V7iSVX3ooomk=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIC+jCCAoGgAwIBAgIGAX5TUU22MAoGCCqGSM49BAMDMCkxJzAlBgoJkiaJk/Is
ZAEBDBd1cm46bXJuOm1jcDppZDphYm9hbWFyZTAeFw0yMjAxMTMxMjAyMjRaFw0y
NDAxMTQxMjAyMjRaMC4xLDAqBgoJkiaJk/IsZAEBDBx1cm46bXJuOm1jcDppZDph
Ym9hbWFyZTp0ZXN0MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEsBZAjjfz5pkH4wGq
rhV+QX5l6EaSkR+4uhobV/dlF4/Oey+8Ps0kYlWczPO9ChJ4IWSgAyln/VVotFBz
FDBZi18KqTXOYHXxVW3FSe4tTRRUb4SSnWAf055icuw3UA7io4IBcTCCAW0wKQYD
VR0RBCIwIKARBgNVBAqgCgwIYWJvYW1hcmWgCwYDVQQGoAQMAkZJMB0GA1UdDgQW
BBR9fwl315Hban8l7jqLoqNw4oi+IDAfBgNVHSMEGDAWgBQUAyiqlNMNArDpc4R+
ChEGs2E3KDALBgNVHQ8EBAMCAIQwEwYDVR0lBAwwCgYIKwYBBQUHAwIwEgYDVR0T
AQH/BAgwBgEB/wIBBDAyBgNVHR8EKzApMCegJaAjhiFodHRwczovL21pci5hYm9h
bWFyZS5uZXQvdGVzdC9jcmwwgZUGCCsGAQUFBwEBBIGIMIGFMC4GCCsGAQUFBzAB
hiJodHRwczovL21pci5hYm9hbWFyZS5uZXQvdGVzdC9vY3NwMFMGFGmC09fB3Oyo
woKNtrDfwcbq/dlYhjtodHRwczovL21pci5hYm9hbWFyZS5uZXQvdGVzdC9jZXJ0
aWZpY2F0ZXMvMDE3ZTUzNTE0ZGI2Lng1dTAKBggqhkjOPQQDAwNnADBkAjAqa8pT
8t/AfeUumlaGKLZgfiN/M6XEMxsb85WdbW9bB116YBUQYq+JBRwjqnGu9DYCMGX/
MD6vsdpTVLuuhG1qNG/CKMAEyOOc5dI1VOtXQo1VfX7wpSS9ObiyPymBYt31Mw==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDGjCCAqCgAwIBAgIGAX5TUSu5MAoGCCqGSM49BAMDMEExPzAPBgNVBAoMCGFi
b2FtYXJlMAkGA1UEBgwCRkkwIQYJKoZIhvcNAQkBDBRtaXJAbWlyLmFib2FtYXJl
Lm5ldDAeFw0yMjAxMTMxMjAyMTVaFw0yNzAxMTMxMjAyMTVaMCkxJzAlBgoJkiaJ
k/IsZAEBDBd1cm46bXJuOm1jcDppZDphYm9hbWFyZTB2MBAGByqGSM49AgEGBSuB
BAAiA2IABFoM2jPF9U9XelQX0Nh7tB1+s7qLoJcsfurDUmyCounvhvpL/pj2nks7
dAYU0fR0LAPMqjobSNX7Pz0Mm/ewB+SH4bCJbgAcoUNjUOgLT5DJ8bLihqfyDjwj
VcwFLP5NY6OCAX0wggF5MCkGA1UdEQQiMCCgEQYDVQQKoAoMCGFib2FtYXJloAsG
A1UEBqAEDAJGSTAdBgNVHQ4EFgQUFAMoqpTTDQKw6XOEfgoRBrNhNygwHwYDVR0j
BBgwFoAUbxloeiYGRySwevU6Cg+EUVg+k1swCwYDVR0PBAQDAgCEMBMGA1UdJQQM
MAoGCCsGAQUFBwMCMBIGA1UdEwEB/wQIMAYBAf8CAQQwNgYDVR0fBC8wLTAroCmg
J4YlaHR0cHM6Ly9taXIuYWJvYW1hcmUubmV0L2Fib2FtYXJlL2NybDCBnQYIKwYB
BQUHAQEEgZAwgY0wMgYIKwYBBQUHMAGGJmh0dHBzOi8vbWlyLmFib2FtYXJlLm5l
dC9hYm9hbWFyZS9vY3NwMFcGFGmC09fB3OyowoKNtrDfwcbq/dlYhj9odHRwczov
L21pci5hYm9hbWFyZS5uZXQvYWJvYW1hcmUvY2VydGlmaWNhdGVzLzAxN2U1MzUx
MmJiOS54NXUwCgYIKoZIzj0EAwMDaAAwZQIwa9iPOVY+0NXlKi2qdHBU0J9ZPsGp
6Fwk26r1/AfSTSXsKBsrOZN+jIgXt9ijTVSZAjEA22vuxm3SFT3rgtbDFLjt/mgD
EK0X4kxFQAmb+V2fJS0h8IxhqImTZyG+k/f+bnq0
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