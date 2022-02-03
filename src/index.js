import pki  from 'pkijs' 
import asn1 from 'asn1js'

import { MRN } from './mrn.js'
import { MCPEntity } from './entity.js'
import { MCPCertificate, } from './certificate.js'
import { OID }  from './mcp-oids.js'
import { JWT } from './jwt.js'
import { Attestation } from './attestations.js'
import { Options } from './options.js'
import Errors from './errors.js'

async function initialize () {
  await MCPCertificate.initialize()
}

export { Attestation, Errors, JWT, initialize, MCPCertificate, MCPEntity, MRN, Options, OID, pki, asn1 }