In the following scenario (software on) a ship requests a certificate from the MIR and subsequently uses that certificate to authenticate to a service by provider by creating a JSON Web Token. The service provider then goes through the steps of the token verification process.

First the ship creates a key pair for itself. In JWK form the key pair could look like:

  ```
  {
    "public": {
      "kty": "EC",
      "x": "NR1g4V6Q2OOGT5nzgys6iVF8ijcmm7XW4r7zicwSfXaaA7PDekOOEVjeoq6SGJ5l",
      "y": "redpwLEmJgOuAJ7drXQblBCBXzMiX-n3sHH7P_9QeP4u4-y87nGCl5EGcDhIqMoP",
      "crv": "P-384"
    },
    "private": {
      "kty": "EC",
      "x": "NR1g4V6Q2OOGT5nzgys6iVF8ijcmm7XW4r7zicwSfXaaA7PDekOOEVjeoq6SGJ5l",
      "y": "redpwLEmJgOuAJ7drXQblBCBXzMiX-n3sHH7P_9QeP4u4-y87nGCl5EGcDhIqMoP",
      "crv": "P-384",
      "d": "QjCXRNIa5Xru3zSnKcXyzmGuLo34kEXBKcJRxSa2VssNy470FlM64JWiP0Hm-srk"
    }
  }
  ```

The ship can now ask a MIR to issue a certificate (and a MRN). In case the MIR uses the [AboaMare Mirabom](https://github.com/aboamare/mirabom) implementation it can be done by submitting a signed JWS structure. The ship claims to be this:

  ```
  {
    "name": "AboaMare Spirit",
    "callSign": "ABCDEF",
    "MMSI": "230999999",
    "homePort": "FI TKU"
  }
  ```

The above structure is used as the payload for the JWS. The newly generated public key and the algorithm are placed in the JWS protected header, which hence looks like:

  ```
  {
    "alg": "ES384",
    "jwk": {
      "kty": "EC",
      "x": "NR1g4V6Q2OOGT5nzgys6iVF8ijcmm7XW4r7zicwSfXaaA7PDekOOEVjeoq6SGJ5l",
      "y": "redpwLEmJgOuAJ7drXQblBCBXzMiX-n3sHH7P_9QeP4u4-y87nGCl5EGcDhIqMoP",
      "crv": "P-384"
    }
  }  
  ```

The ship uses the generated private key to sign the JWS, which in "flattened JSON" form looks like:

  ```
  {
    "signature": "aXo66Q7_C6aX9ZsIMTzsuCC_K-VZl4VJTV4_nKigB3ulwBBd6E8TkQJyBnM4qGTJc4Du4Sfnbi4o_QBeBBL6Y2Hh4KX4B5O7f85WLrmRRZmUIWT4ay7EqxDs0AIWlogb",
    "payload": "eyJuYW1lIjoiQWJvYU1hcmUgU3Bpcml0IiwiY2FsbFNpZ24iOiJBQkNERUYiLCJNTVNJIjoiMjMwOTk5OTk5IiwiaG9tZVBvcnQiOiJGSSBUS1UifQ",
    "protected": "eyJhbGciOiJFUzM4NCIsImp3ayI6eyJrdHkiOiJFQyIsIngiOiJOUjFnNFY2UTJPT0dUNW56Z3lzNmlWRjhpamNtbTdYVzRyN3ppY3dTZlhhYUE3UERla09PRVZqZW9xNlNHSjVsIiwieSI6InJlZHB3TEVtSmdPdUFKN2RyWFFibEJDQlh6TWlYLW4zc0hIN1BfOVFlUDR1NC15ODduR0NsNUVHY0RoSXFNb1AiLCJjcnYiOiJQLTM4NCJ9fQ"
  }
  ```

Of course the ship should store its private key in a safe location!

Now the ship submits the JWS to the MIR. In our case to the AboaMare Test MIR, as a HTTP PUT request with the JWS as the body:

  ```
  PUT /test/certificates HTTP/1.1
  Content-Type: application/json
  User-Agent: PostmanRuntime/7.28.4
  Accept: */*
  Host: localhost:3001
  Accept-Encoding: gzip, deflate, br
  Connection: keep-alive
  Content-Length: 561
  
  {
  "signature": "aXo66Q7_C6aX9ZsIMTzsuCC_K-VZl4VJTV4_nKigB3ulwBBd6E8TkQJyBnM4qGTJc4Du4Sfnbi4o_QBeBBL6Y2Hh4KX4B5O7f85WLrmRRZmUIWT4ay7EqxDs0AIWlogb",
  "payload": "eyJuYW1lIjoiQWJvYU1hcmUgU3Bpcml0IiwiY2FsbFNpZ24iOiJBQkNERUYiLCJNTVNJIjoiMjMwOTk5OTk5IiwiaG9tZVBvcnQiOiJGSSBUS1UifQ",
  "protected": "eyJhbGciOiJFUzM4NCIsImp3ayI6eyJrdHkiOiJFQyIsIngiOiJOUjFnNFY2UTJPT0dUNW56Z3lzNmlWRjhpamNtbTdYVzRyN3ppY3dTZlhhYUE3UERla09PRVZqZW9xNlNHSjVsIiwieSI6InJlZHB3TEVtSmdPdUFKN2RyWFFibEJDQlh6TWlYLW4zc0hIN1BfOVFlUDR1NC15ODduR0NsNUVHY0RoSXFNb1AiLCJjcnYiOiJQLTM4NCJ9fQ"
  }
  ```

The MIR does it thing (it should really do a lot of checks, as in actual paperwork, but this "Test" MIR trusts every request), issues an MRN, and creates a certificate. It responds with the MRN and a URL that can be used to retrieve the certificate chain. The chain will have the new certificate for the ship, and the certificate of the "Test MIR", and the certificate of the MIR that issued that "Test MIR" certificate, etc.

  ```
  HTTP/1.1 200 OK
  content-type: application/json; charset=utf-8
  cache-control: no-cache
  content-length: 150
  Date: Thu, 30 Dec 2021 15:47:33 GMT
  Connection: keep-alive
  Keep-Alive: timeout=5
  
  {
    "MRN":"urn:mrn:mcp:id:aboamare:test:aboamare-spirit",
    "x5u":"https://mir.aboamare.net/test/certificates/9432fcc7bc3343bb3b48f2e07369ac19536076ec.x5u"
  }
  ```

Now let's assume some service provider (e.g. an MMS Router) has requested to ship to authenticate itself by submitting a JWS over a nonce. Let's assume the nonce given by the service provider (in some sort of authentication request) is `bohQwng72K`.
The ship now again creates a _JSON Web **Token**_ with payload like:

  ```
  {
    "nonce": "bohQwng72K",
    "sub": "urn:mrn:mcp:id:aboamare:test:aboamare-spirit",
    "iat": 1640885235,
    "exp": 1640892435
  }
  ```
and with the protected header that has the *x5u* as follows:
  ```
  {
  "alg": "ES384",
  "x5u": "https://mir.aboamare.net/test/certificates/1da3a11b1ab76ea926b51ff95c793b71ea175e33.x5u"
  }
  ```

When signed with the private key from above the resulting JWT looks like:

  ```
  eyJhbGciOiJFUzM4NCIsIng1dSI6Imh0dHBzOi8vbWlyLmFib2FtYXJlLm5ldC90ZXN0L2NlcnRpZmljYXRlcy8xZGEzYTExYjFhYjc2ZWE5MjZiNTFmZjk1Yzc5M2I3MWVhMTc1ZTMzLng1dSJ9.eyJub25jZSI6ImJvaFF3bmc3MksiLCJzdWIiOiJ1cm46bXJuOm1jcDppZDphYm9hbWFyZTp0ZXN0OmFib2FtYXJlLXNwaXJpdCIsImlhdCI6MTY0MDg4NTIzNSwiZXhwIjoxNjQwODkyNDM1fQ.L28PGA2L9SLrFQN9OvG9p1MLjWZX8xe9C-60i23rhW0Hvq4u00hkuTTss6EKJg0iGJiwhnZ-sZpObBLWS6vVwwft_90oWg2z-xEVzaHsu3qRqkol2bFXVclCcDcij4Gg
  ```

Note that a JWT is always a plain, longish, string. Whereas a JWS (as used to obtain a certificate) can be in JSON form.

To actually authenticate itself the ship submits this JWT to the service provider. The service provider needs to decode and verify the JWT and then establish if it can trust that the "ship" indeed is what it _claims_ to be. It is this validation that can be taken care of by the **MiraU** code in this repository. Even with a linrary doing most of the work it is good to understand what should be done.  

First the service provider needs to decode the protected header to get the "x5u", i.e. the URL to the certificate chain. The service provider can then fetch the certificate chain with a HTTP GET.....

  ```
  GET /test/certificates/9432fcc7bc3343bb3b48f2e07369ac19536076ec.x5u HTTP/1.1
  User-Agent: PostmanRuntime/7.28.4
  Accept: */*
  Host: localhost:3001
  Accept-Encoding: gzip, deflate, br
  Connection: keep-alive
  ```

and receives the chain of certificates in PEM format:

  ```
  HTTP/1.1 200 OK
  content-type: text/plain; charset=utf-8
  cache-control: no-cache
  vary: accept-encoding
  content-encoding: gzip
  Date: Thu, 30 Dec 2021 17:30:03 GMT
  Connection: keep-alive
  Keep-Alive: timeout=5
  Transfer-Encoding: chunked
  
  -----BEGIN CERTIFICATE-----
  MIIC9DCCAnmgAwIBAgIGAX4MVvjkMAoGCCqGSM49BAMDMC4xLDAqBgoJkiaJk/Is
  ZAEBDBx1cm46bXJuOm1jcDppZDphYm9hbWFyZTp0ZXN0MB4XDTIxMTIzMDE3MTUz
  M1oXDTIzMTIzMTE3MTUzM1owPjE8MDoGCgmSJomT8ixkAQEMLHVybjptcm46bWNw
  OmlkOmFib2FtYXJlOnRlc3Q6YWJvYW1hcmUtc3Bpcml0MHYwEAYHKoZIzj0CAQYF
  K4EEACIDYgAENR1g4V6Q2OOGT5nzgys6iVF8ijcmm7XW4r7zicwSfXaaA7PDekOO
  EVjeoq6SGJ5lredpwLEmJgOuAJ7drXQblBCBXzMiX+n3sHH7P/9QeP4u4+y87nGC
  l5EGcDhIqMoPo4IBVDCCAVAwcgYDVR0RBGswaaAgBhRpgrmI8MCbr/jHy6m9wICq
  rteKG6AIDAZBQkNERUagIwYUaYPuloSAm6/4x8uLqcCAqq7XihugCwwJMjMwOTk5
  OTk5oCAGFGmDreLv99u5krbJoo3fjpC7/+5LoAgMBkZJIFRLVTAdBgNVHQ4EFgQU
  p8VMbYqWwowvusyGGw1xswy55IQwHwYDVR0jBBgwFoAUoRxLRep7qHEbNfgCJzwZ
  oavKEMowCwYDVR0PBAQDAgCAMBkGA1UdJQQSMBAGBFUdJQAGCCsGAQUFBwMCMDIG
  A1UdHwQrMCkwJ6AloCOGIWh0dHBzOi8vbWlyLmFib2FtYXJlLm5ldC90ZXN0L2Ny
  bDA+BggrBgEFBQcBAQQyMDAwLgYIKwYBBQUHMAGGImh0dHBzOi8vbWlyLmFib2Ft
  YXJlLm5ldC90ZXN0L29jc3AwCgYIKoZIzj0EAwMDaQAwZgIxAK6F/LbToC4maeh6
  bTlATOSS3HD64ql6SwZ1MftTwAU15P5wzzPvH16FHXOcJ20w1gIxAMWhsarEdB5j
  Wy3wfoheQzJpEYiJiB5h+26NkkAZcCFWNhIL7RFM0GNiV6kkDq97Hw==
  -----END CERTIFICATE-----
  -----BEGIN CERTIFICATE-----
  MIICozCCAimgAwIBAgIGAX4MUfkUMAoGCCqGSM49BAMDMCkxJzAlBgoJkiaJk/Is
  ZAEBDBd1cm46bXJuOm1jcDppZDphYm9hbWFyZTAeFw0yMTEyMzAxNzEwMDVaFw0y
  MzEyMzExNzEwMDVaMC4xLDAqBgoJkiaJk/IsZAEBDBx1cm46bXJuOm1jcDppZDph
  Ym9hbWFyZTp0ZXN0MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEuKYyaPehHynwBO5Z
  UY0ws44nUEThg0InymMj3LpF1ERyhFctCvq+TTeSM6QQNDJHKofNwHe4L8Hx9a2g
  ud5DeAT6QpioKzv9tHeiyopcuJSd0vDoUuy0RvVl1E6ckT3Mo4IBGTCCARUwKQYD
  VR0RBCIwIKARBgNVBAqgCgwIYWJvYW1hcmWgCwYDVQQGoAQMAkZJMB0GA1UdDgQW
  BBShHEtF6nuocRs1+AInPBmhq8oQyjAfBgNVHSMEGDAWgBRhyN5jwtaqT8bGzRqz
  TLyq1e/jFjALBgNVHQ8EBAMCAIQwEwYDVR0lBAwwCgYIKwYBBQUHAwIwEgYDVR0T
  AQH/BAgwBgEB/wIBBDAyBgNVHR8EKzApMCegJaAjhiFodHRwczovL21pci5hYm9h
  bWFyZS5uZXQvdGVzdC9jcmwwPgYIKwYBBQUHAQEEMjAwMC4GCCsGAQUFBzABhiJo
  dHRwczovL21pci5hYm9hbWFyZS5uZXQvdGVzdC9vY3NwMAoGCCqGSM49BAMDA2gA
  MGUCMQDSXdSM1uUBm2teC3Tn+SHMgLegFXd/19D3z+Naf6eHAEk9SwesrUPtHgIs
  oc45yjsCMFcJEQF/26Oi7Pr/Vur7N6FwGoywz8jakCb20kF5bYpcL5QydnnwXWTc
  KvVpH7Kvrg==
  -----END CERTIFICATE-----
  -----BEGIN CERTIFICATE-----
  MIICvjCCAkSgAwIBAgIGAX4MTa/LMAoGCCqGSM49BAMDMEExPzAPBgNVBAoMCGFi
  b2FtYXJlMAkGA1UEBgwCRkkwIQYJKoZIhvcNAQkBDBRtaXJAbWlyLmFib2FtYXJl
  Lm5ldDAeFw0yMTEyMzAxNzA1MjRaFw0yNjEyMzAxNzA1MjRaMCkxJzAlBgoJkiaJ
  k/IsZAEBDBd1cm46bXJuOm1jcDppZDphYm9hbWFyZTB2MBAGByqGSM49AgEGBSuB
  BAAiA2IABGu9PktfZN36wGw5E/vgWr91jU2+oOLwkz1VtP69O2b2u36qpI7tdfQT
  mlHJgpir2gUU1jyfRmwlmipyWtxzkKcs71ZUuwFDPqjb3UQEv8Yw5IuodDfaggBg
  OP3BL76fi6OCASEwggEdMCkGA1UdEQQiMCCgEQYDVQQKoAoMCGFib2FtYXJloAsG
  A1UEBqAEDAJGSTAdBgNVHQ4EFgQUYcjeY8LWqk/Gxs0as0y8qtXv4xYwHwYDVR0j
  BBgwFoAUTa57hGAdTipkTNxPmO0XW+OkP7owCwYDVR0PBAQDAgCEMBMGA1UdJQQM
  MAoGCCsGAQUFBwMCMBIGA1UdEwEB/wQIMAYBAf8CAQQwNgYDVR0fBC8wLTAroCmg
  J4YlaHR0cHM6Ly9taXIuYWJvYW1hcmUubmV0L2Fib2FtYXJlL2NybDBCBggrBgEF
  BQcBAQQ2MDQwMgYIKwYBBQUHMAGGJmh0dHBzOi8vbWlyLmFib2FtYXJlLm5ldC9h
  Ym9hbWFyZS9vY3NwMAoGCCqGSM49BAMDA2gAMGUCMD0UUCSsPU3T0vf9/KyqfPbn
  pOQ8lD3qit9fM8CvuSh874bFJkYhwH4nyWwrbBu0JQIxAOTrLsPbusfcEM0slN9H
  GVBRtINa80Lkyge/u+7nosq5tkzKHb9BnccBKl45jZzsAw==
  -----END CERTIFICATE-----
  ```

The service provider now decodes and parses the first (top-most) certificate which results in something like:

  ```
  Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1640884533476 (0x17e0c56f8e4)
    Signature Algorithm: ecdsa-with-SHA384
    Issuer: UID=urn:mrn:mcp:id:aboamare:test
    Validity
        Not Before: Dec 30 17:15:33 2021 GMT
        Not After : Dec 31 17:15:33 2023 GMT
    Subject: UID=urn:mrn:mcp:id:aboamare:test:aboamare-spirit
    Subject Public Key Info:
        Public Key Algorithm: id-ecPublicKey
            Public-Key: (384 bit)
            pub: 
                04:35:1d:60:e1:5e:90:d8:e3:86:4f:99:f3:83:2b:
                3a:89:51:7c:8a:37:26:9b:b5:d6:e2:be:f3:89:cc:
                12:7d:76:9a:03:b3:c3:7a:43:8e:11:58:de:a2:ae:
                92:18:9e:65:ad:e7:69:c0:b1:26:26:03:ae:00:9e:
                dd:ad:74:1b:94:10:81:5f:33:22:5f:e9:f7:b0:71:
                fb:3f:ff:50:78:fe:2e:e3:ec:bc:ee:71:82:97:91:
                06:70:38:48:a8:ca:0f
            ASN1 OID: secp384r1
            NIST CURVE: P-384
    X509v3 extensions:
        X509v3 Subject Alternative Name: 
            othername:<unsupported>, othername:<unsupported>, othername:<unsupported>
        X509v3 Subject Key Identifier: 
            A7:C5:4C:6D:8A:96:C2:8C:2F:BA:CC:86:1B:0D:71:B3:0C:B9:E4:84
        X509v3 Authority Key Identifier: 
            keyid:A1:1C:4B:45:EA:7B:A8:71:1B:35:F8:02:27:3C:19:A1:AB:CA:10:CA

        X509v3 Key Usage: 
            Digital Signature
        X509v3 Extended Key Usage: 
            Any Extended Key Usage, TLS Web Client Authentication
        X509v3 CRL Distribution Points: 

            Full Name:
              URI:https://mir.aboamare.net/test/crl

        Authority Information Access: 
            OCSP - URI:https://mir.aboamare.net/test/ocsp
  ```

The server provider should now first check if the _UID_ of the _Subject_ in this certificate matches the claimed _sub_ in the (payload of the) JWT. If that's the case it can be assumed that the Subjct Public Key Info in the certificate contains the public key of the ship. So with that key the service provider can verify the JWT, i.e. asseert that the JWT was signed with the private key of the ship.

Next the service provider should verify each of the remaining certificates in the chain. Note that UID of the ship starts with the Issuer UID in the ship cert. In fact the Issuer UID should be equal to the ship UID up to (but not including) the last colon character in the ship UID. And of course the next (second) certificate should have a DN UID that is exactly the same as the Issuer UID in the first (ship) cert. So let's look at that next, second, certificate. When decoded it has (truncated):

  ```
  Certificate:
      Data:
          Version: 3 (0x2)
          Serial Number: 1640884205844 (0x17e0c51f914)
      Signature Algorithm: ecdsa-with-SHA384
      Issuer: UID=urn:mrn:mcp:id:aboamare
      Validity
          Not Before: Dec 30 17:10:05 2021 GMT
          Not After : Dec 31 17:10:05 2023 GMT
      Subject: UID=urn:mrn:mcp:id:aboamare:test
      Subject Public Key Info:
          ...
  ```
So far, so good. The Subject UID here is indeed the same as the Issuer UID of the ship certificate. Moreover, the service provider now can, and should, verify that the signature in the ship certificate indeed was created with the private key that belongs to the public key in this second certificate. Note that this second certificate was issued to the AboaMare *Test MIR*, by the MIR that should be in the next, third, certificate.

For each certificate there are additional aspects to check, such as the validity. Each certificate should also be checked for being revoked, either from a CRL (Certificate Revocation List) or, preferably, from the OCSP end point.

The last certificate in the chain should either be directly trusted by the service provider, or the service provider can check if this certificate, and hence the MIR to which that certificae was issued, is _endorsed_ by the Marine Connective Consortium, or by other organizations that the Service Provider has faith in.

The service provider could now annotate the certificates with some status information and cache that for a reasonable amount of time, e.g. 24 hours. Within such period the service provider would not have to go through the same full chain of certificates if another (or the same) entity authenticates with a certificate that was issued by the same MIR.
