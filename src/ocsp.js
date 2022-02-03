import crypto from 'crypto'
import fetch from 'isomorphic-unfetch'

import pki from 'pkijs'
import asn1 from 'asn1js'

import { OID }  from './mcp-oids.js'
import Errors from './errors.js'

const { CertificateError } = Errors

function bufToHex (buffer) { // buffer is an ArrayBuffer
  return [...new Uint8Array(buffer)]
    .map(x => x.toString(16).padStart(2, '0'))
    .join('')
}

function nameHash (dn = {uid: 'urn:mrn:mcp:id:aboamare:test'}) {
  const rdn = new pki.RelativeDistinguishedNames()
  rdn.typesAndValues.push(...Object.keys(dn).map(attr => {
    let asn1Type = asn1.Utf8String
    const value = dn[attr]
    if (Number.isInteger(value)) {
      asn1Type = asn1.Integer
    }
    return new pki.AttributeTypeAndValue({type: OID[attr], value: new asn1Type({ value })})
  }))

  const rdnBytes = rdn.toSchema().toBER(false)
  const result = crypto.createHash('sha1').update(Buffer.from(rdnBytes)).digest()
  return result
}

function request (spid, pkiCert) {
  const req = new pki.OCSPRequest()

  req.url = pkiCert.ocspUrl

  req.tbsRequest.requestorName = new pki.GeneralName({
		type: 4,
		value: new pki.RelativeDistinguishedNames({
			typesAndValues: [
				new pki.AttributeTypeAndValue({
					type: OID.uid,
					value: new asn1.PrintableString({ value: spid })
				})
			]
		})
  })

  req.tbsRequest.requestList = [new pki.Request({
		reqCert: new pki.CertID({
			hashAlgorithm: new pki.AlgorithmIdentifier({
				algorithmId: OID.sha1
			}),
			issuerNameHash: new asn1.OctetString({ valueHex: nameHash({ uid: pkiCert.ipid }) }),
			issuerKeyHash: new asn1.OctetString({ valueHex: pkiCert.authorityKeyIdentifier.valueBlock.valueHex }),
			serialNumber: new asn1.Integer({ valueHex: pkiCert.serialNumber.valueBlock.valueHex })
		})
	})]

  const nonce = crypto.randomFillSync(new ArrayBuffer(8))
  req.tbsRequest.requestExtensions = [
		new pki.Extension({
			extnID: OID.nonce,
			extnValue: nonce
		})
	]
  req.nonce = bufToHex(nonce)

  return req
}

async function response (fetchResponse) {
  const der = await fetchResponse.arrayBuffer()
  const res = new pki.OCSPResponse({schema: asn1.fromBER(der).result})

  res.statuses = {}

  switch(res.responseStatus.valueBlock.valueDec)
	{
		case 0:
			res.status = "successful"
			break
		case 1:
			res.status = "malformedRequest"
			break
		case 2:
			res.status = "internalError"
			break
		case 3:
			res.status = "tryLater"
			break
		case 4:
			res.status = "<not used>"
			break
		case 5:
			res.status = "sigRequired"
			break
		case 6:
			res.status = "unauthorized"
			break
		default:
			alert("Wrong OCSP response status")
			return
	}

  if (res.responseBytes) {
    const ocspBasicResp = new pki.BasicOCSPResponse({ schema: (asn1.fromBER(res.responseBytes.response.valueBlock.valueHex)).result })
    if (ocspBasicResp.tbsResponseData.responderID instanceof pki.RelativeDistinguishedNames) {
      res.responder = ocspBasicResp.tbsResponseData.responderID.typesAndValues.reduce((obj, typeAndValue) => {
        const oidName = OID[typeAndValue.type]
        if (oidName) {
          obj[oidName] = typeAndValue.value.valueBlock.value
        }
        return obj
      }, {})
    }

    ocspBasicResp.tbsResponseData.responseExtensions.forEach(extn => {
      if (extn.extnID === OID.nonce) {
        res.nonce = bufToHex(extn.extnValue.valueBlock.valueHex)
      }
    })

    ocspBasicResp.tbsResponseData.responses.forEach(singleResponse => {
      const serial = bufToHex(singleResponse.certID.serialNumber.valueBlock.valueHex)
      let status = undefined
      switch(singleResponse.certStatus.idBlock.tagNumber)
      {
        case 0:
          status = 'good'
          break
        case 1:
          status = {revoked: singleResponse.certStatus.valueBlock.value}
          break
        case 2:
        default:
          status = undefined
      }
      res.statuses[serial] = status
    })

  }

  return res
}

export async function getStatus(spid, certificate) {
  try {
    const ocspReq = request(spid, certificate)

    const url = new URL(ocspReq.url)
    if (spid === 'urn:mrn:mcp:id:aboamare:test:sp') {
      url.host = 'localhost:3001'
      url.protocol = 'http'
    }

    const resp = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/ocsp-request'
      },
      body: ocspReq.toSchema(true).toBER(false)
    })

    if (resp.ok) {
      const ocspResponse = await response(resp)
      if (ocspResponse.nonce !== ocspReq.nonce) {
        throw CertificateError.OCSPError(ocspReq)
      }
      //TODO: ocspBasicResp.verify({ trustedCerts: trustedCertificates })
      return ocspResponse.statuses[certificate.serialNumber.toLowerCase()]
    } else {
      return undefined
    }
  } catch (err) {
    if (err.name === 'FetchError') {
      console.warn(err.message)
    } else {
      console.debug(err)
    }
    return undefined // undefined means "unknown"
  }

}

export default { getStatus }