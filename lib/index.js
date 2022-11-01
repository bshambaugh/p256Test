import { P256Provider } from 'key-did-provider-p256';
import KeyResolver from 'key-did-resolver';
import { DID } from 'dids';
import { fromString } from 'uint8arrays';
const privateKey = '040f1dbf0a2ca86875447a7c010b0fc6d39d76859c458fbe8f2bf775a40ad74a';
const provider = new P256Provider(fromString(privateKey, 'hex'));
const did = new DID({ provider, resolver: KeyResolver.getResolver() });
console.log(did);
const result = await did.authenticate();
console.log(did.id);
const { jws, linkedBlock } = await did.createDagJWS({ hello: 'world' });
console.log(jws);
await did.verifyJWS(jws);
//# sourceMappingURL=index.js.map