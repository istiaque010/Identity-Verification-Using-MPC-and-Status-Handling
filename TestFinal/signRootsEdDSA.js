const crypto = require('crypto');

// Step 1: Generate Ed25519 key pair
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

// Step 2: Message to sign
// const message = '546444071fe506bc07018a4e1d6922e9f6c4853b31bcf3a2bdeec366f8e89ec8';  // VC1
//const message = '13a2a43463a8b9f2b20b37f9c00081dff295bc2f69746ca1489470a7060a9fa3';  // VC2
//const message = 'dc7b9ba847d5ca7d6c5957b219184d3c4940c9a417b83b37626bb488383ad6b5';  // VC3
const message = 'c1a5cf51f806e4ee63a7405cae8bb09596222a17f2dbeaab5c8eda6522c2eb45';  // VP

// Step 3: Sign and time it
const signStart = process.hrtime.bigint();

const signature = crypto.sign(null, Buffer.from(message, 'utf8'), {
  key: privateKey
});

const signEnd = process.hrtime.bigint();
const signTimeMs = Number(signEnd - signStart) / 1e6;

// Step 4: Create the proof object
const proof = {
  type: 'Ed25519Signature2020',
  created: new Date().toISOString(),
  signature: signature.toString('base64'),
  publicKeyPem: publicKey,
  signTimeMs: signTimeMs.toFixed(3) + ' ms'
};

// Step 5: Create signed package
const signedPayload = {
  message,
  proof
};

console.log(' Signed payload:\n', JSON.stringify(signedPayload, null, 2));

// Step 6: Verifier side — verify and time it
function verifyProof({ message, proof }) {
  const verifyStart = process.hrtime.bigint();

  const isValid = crypto.verify(
    null,
    Buffer.from(message, 'utf8'),
    {
      key: proof.publicKeyPem
    },
    Buffer.from(proof.signature, 'base64')
  );

  const verifyEnd = process.hrtime.bigint();
  const verifyTimeMs = Number(verifyEnd - verifyStart) / 1e6;

  console.log('\n Verification result:');
  console.log(' Signature valid?', isValid);
  console.log(' Verification time:', verifyTimeMs.toFixed(3), 'ms');

  return { isValid, verifyTimeMs };
}

// Step 7: Run verifier
verifyProof(signedPayload);
