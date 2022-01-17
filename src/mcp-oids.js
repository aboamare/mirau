const OID = {
  /*
   * standard OIDs needed in MCP certificates
  */
  country:      '2.5.4.6',                  // C
  name:         '2.5.4.3',                  // CN
  email:        '1.2.840.113549.1.9.1',     // E
  organization: '2.5.4.10',                 // O
  unit:         '2.5.4.11',                 // OU
  UID:          '0.9.2342.19200300.100.1.1',


  /*
   * (OCSP) algorithms and extensions
   */
  sha1:         '1.3.14.3.2.26',
  sha256:       '2.16.840.1.101.3.4.2.1',
  nonce:        '1.3.6.1.5.5.7.48.1.2',

  /*
   * Extended Key Usage OIDs
   */
  anyKeyUsage:      '2.5.29.37.0',       // anyExtendedKeyUsage
  serverAuth:       '1.3.6.1.5.5.7.3.1', // id-kp-serverAuth
  clientAuth:       '1.3.6.1.5.5.7.3.2', // id-kp-clientAuth
  codeSigning:      '1.3.6.1.5.5.7.3.3', // id-kp-codeSigning
  emailProtection:  '1.3.6.1.5.5.7.3.4', // id-kp-emailProtection
  timeStamping:     '1.3.6.1.5.5.7.3.8', // id-kp-timeStamping
  OCSPSigning:      '1.3.6.1.5.5.7.3.9', // id-kp-OCSPSigning
  
  /*
   * Other standard extensions
   */
  subjectAltName:         '2.5.29.17',          // id-ce 17
  authorityKeyIdentifier: '2.5.29.35',          // id-ce 35
  subjectKeyIdentifier:   '2.5.29.14',          // id-ce 14
  crlDistributionPoints:  '2.5.29.31',          // id-ce 31
  authorityInfoAccess:    '1.3.6.1.5.5.7.1.1',  // id-pe 1
  subjectInfoAccess:      '1.3.6.1.5.5.7.1.11', // id-pe 11
  
  /*
   * Authority Information Access Methods
   */
  ocsp: '1.3.6.1.5.5.7.48.1', // id-ad-ocsp
  x5u:  '2.25.225758541249626787560521749862278982872', // MCP defined url to get certificate chain, like x5u in JSON Web Signatures.

  /*
   * Subject Information Access Methods
   */
  matp:         '2.25.110111187235111034673021170401583226313', // MCP defined URL to get list of attestors or an attestation

  /*
   * MCP defined OIDs for the Subject Alternative Names
   */
  flagState:    '2.25.323100633285601570573910217875371967771',
  callSign:     '2.25.208070283325144527098121348946972755227',
  IMONumber:    '2.25.291283622413876360871493815653100799259',
  MMSI:         '2.25.328433707816814908768060331477217690907',
  shipType:     '2.25.107857171638679641902842130101018412315',
  homePort:     '2.25.285632790821948647314354670918887798603',
  secondaryMRN: '2.25.268095117363717005222833833642941669792',
  URL:          '2.25.245076023612240385163414144226581328607'
}

Object.entries(OID).forEach(entry => {
  OID[entry[1]] = entry[0]
})

export { OID }