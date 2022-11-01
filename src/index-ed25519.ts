import { Ed25519Provider } from 'key-did-provider-ed25519'
import KeyResolver from 'key-did-resolver'
import { DID } from 'dids'


const seed = new Uint8Array(32) //  32 bytes with high entropy
console.log(seed)
const provider = new Ed25519Provider(seed)
const did = new DID({ provider, resolver: KeyResolver.getResolver() })
console.log(did)

const result = await did.authenticate()
//did.authenticate()   .. this won't allow the other functions below to run...
/*
let quth = async() => await did.authenticate()
*/
// log the DID
console.log(did.id)

// create JWS
const { jws, linkedBlock } = await did.createDagJWS({ hello: 'world' })
console.log(jws)

// verify JWS
await did.verifyJWS(jws)

// create JWE
const jwe = await did.createDagJWE({ very: 'secret' }, [did.id])
console.log(jwe);

// decrypt JWE
const decrypted = await did.decryptDagJWE(jwe)
console.log(decrypted)
