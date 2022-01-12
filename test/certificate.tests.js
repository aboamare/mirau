import chai from 'chai'
import chaiThings from 'chai-things'

chai.should()
chai.use(chaiThings)
const expect = chai.expect

import { MCPCertificate } from '../src/certificate.js'

const pemChain = `-----BEGIN CERTIFICATE-----
MIIC8zCCAnmgAwIBAgIGAX5Oo2ozMAoGCCqGSM49BAMDMC4xLDAqBgoJkiaJk/Is
ZAEBDBx1cm46bXJuOm1jcDppZDphYm9hbWFyZTp0ZXN0MB4XDTIyMDExMjE0MTM1
OVoXDTI0MDExMzE0MTM1OVowPjE8MDoGCgmSJomT8ixkAQEMLHVybjptcm46bWNw
OmlkOmFib2FtYXJlOnRlc3Q6YWJvYW1hcmUtc3Bpcml0MHYwEAYHKoZIzj0CAQYF
K4EEACIDYgAENR1g4V6Q2OOGT5nzgys6iVF8ijcmm7XW4r7zicwSfXaaA7PDekOO
EVjeoq6SGJ5lredpwLEmJgOuAJ7drXQblBCBXzMiX+n3sHH7P/9QeP4u4+y87nGC
l5EGcDhIqMoPo4IBVDCCAVAwcgYDVR0RBGswaaAgBhRpgrmI8MCbr/jHy6m9wICq
rteKG6AIDAZBQkNERUagIwYUaYPuloSAm6/4x8uLqcCAqq7XihugCwwJMjMwOTk5
OTk5oCAGFGmDreLv99u5krbJoo3fjpC7/+5LoAgMBkZJIFRLVTAdBgNVHQ4EFgQU
p8VMbYqWwowvusyGGw1xswy55IQwHwYDVR0jBBgwFoAUcJ9pfq0PNbNk3zidGxAG
8KPNnJkwCwYDVR0PBAQDAgCAMBkGA1UdJQQSMBAGBFUdJQAGCCsGAQUFBwMCMDIG
A1UdHwQrMCkwJ6AloCOGIWh0dHBzOi8vbWlyLmFib2FtYXJlLm5ldC90ZXN0L2Ny
bDA+BggrBgEFBQcBAQQyMDAwLgYIKwYBBQUHMAGGImh0dHBzOi8vbWlyLmFib2Ft
YXJlLm5ldC90ZXN0L29jc3AwCgYIKoZIzj0EAwMDaAAwZQIxAJNeKh9wmYitSomx
xCSoCO6+unoioJ0kbERTnc4NC5/d/Odi/OqfDxRz1inO5n/1tQIwF9tTimTkvWHA
99RS9aWfRPjAkTRKmubpnEVEKSoKrqeZlNdY+Jacr/bgo4P8udO7
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICojCCAimgAwIBAgIGAX41/SMkMAoGCCqGSM49BAMDMCkxJzAlBgoJkiaJk/Is
ZAEBDBd1cm46bXJuOm1jcDppZDphYm9hbWFyZTAeFw0yMjAxMDcxOTIxMjlaFw0y
NDAxMDgxOTIxMjlaMC4xLDAqBgoJkiaJk/IsZAEBDBx1cm46bXJuOm1jcDppZDph
Ym9hbWFyZTp0ZXN0MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8WFonedVQ7m5ZkQv
WKVvTkKfxUgp3dhJXjc3/HCbcdJ3rhFyvifY87kuWkNr+1ql/AovBnHrUOgg1WsJ
WeSu7DiQtcWfbgRBXXuz29fbpNT4vvJt3zlm9r57C6WnLhRzo4IBGTCCARUwKQYD
VR0RBCIwIKARBgNVBAqgCgwIYWJvYW1hcmWgCwYDVQQGoAQMAkZJMB0GA1UdDgQW
BBRwn2l+rQ81s2TfOJ0bEAbwo82cmTAfBgNVHSMEGDAWgBSDj0ZMSReP0ysPAgoJ
/ZYU+Lk2NDALBgNVHQ8EBAMCAIQwEwYDVR0lBAwwCgYIKwYBBQUHAwIwEgYDVR0T
AQH/BAgwBgEB/wIBBDAyBgNVHR8EKzApMCegJaAjhiFodHRwczovL21pci5hYm9h
bWFyZS5uZXQvdGVzdC9jcmwwPgYIKwYBBQUHAQEEMjAwMC4GCCsGAQUFBzABhiJo
dHRwczovL21pci5hYm9hbWFyZS5uZXQvdGVzdC9vY3NwMAoGCCqGSM49BAMDA2cA
MGQCMGC7MiFTBJe7HQoW7uFK59VUxaP9A/c1isNBTEfWm1xddDDccL/IcEdbMLI2
+Va4qAIwHdswaM6iQDuW5zZxVbyoOqAgxG1xmJlcjx3a4A4kQ6y9wueXmLentq0S
qRkNfHDD
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICvjCCAkSgAwIBAgIGAX4wzfzLMAoGCCqGSM49BAMDMEExPzAPBgNVBAoMCGFi
b2FtYXJlMAkGA1UEBgwCRkkwIQYJKoZIhvcNAQkBDBRtaXJAbWlyLmFib2FtYXJl
Lm5ldDAeFw0yMjAxMDYxOTExNTNaFw0yNzAxMDYxOTExNTNaMCkxJzAlBgoJkiaJ
k/IsZAEBDBd1cm46bXJuOm1jcDppZDphYm9hbWFyZTB2MBAGByqGSM49AgEGBSuB
BAAiA2IABE7TrSrO1An8KfrunT+zMZZAW97mCjtKmWhyn9F39tGMqm1lJUL9flN7
K8MapVMttjaneShB7fpnK/Xo04W/RN7+KBsSo1m2m8jUxKWIVvToxVAVpIHOODvh
eDLVfVh4DqOCASEwggEdMCkGA1UdEQQiMCCgEQYDVQQKoAoMCGFib2FtYXJloAsG
A1UEBqAEDAJGSTAdBgNVHQ4EFgQUg49GTEkXj9MrDwIKCf2WFPi5NjQwHwYDVR0j
BBgwFoAUWhoKa4MVvc1fNHZzUoFeZszyAB0wCwYDVR0PBAQDAgCEMBMGA1UdJQQM
MAoGCCsGAQUFBwMCMBIGA1UdEwEB/wQIMAYBAf8CAQQwNgYDVR0fBC8wLTAroCmg
J4YlaHR0cHM6Ly9taXIuYWJvYW1hcmUubmV0L2Fib2FtYXJlL2NybDBCBggrBgEF
BQcBAQQ2MDQwMgYIKwYBBQUHMAGGJmh0dHBzOi8vbWlyLmFib2FtYXJlLm5ldC9h
Ym9hbWFyZS9vY3NwMAoGCCqGSM49BAMDA2gAMGUCMGdfBQjDdb7C8wcf1GcUmk6t
7DnmlsgE1LlFXJGuGAKg6t8m+1XCBQ4c6Z21S5rURwIxAMlpZBSabNhPyNwTQPcc
/90ovvGskIYBDnc5uQC8afAGy7wWQyyF170ezPt7VVmaiA==
-----END CERTIFICATE-----`

describe('Certificates', function () {
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

  it('validate ok chain', async function () {
    const chain = MCPCertificate.fromPEM(pemChain, true)
    await MCPCertificate.validate(chain, 'urn:mrn:mcp:id:aboamare:test:aboamare-spirit', {spid: 'urn:mrn:mcp:id:aboamare:test:sp'})
  })
})