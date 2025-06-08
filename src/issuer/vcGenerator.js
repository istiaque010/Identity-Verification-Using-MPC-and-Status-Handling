const { signVCVP, generateBBSProof } = require('../crypto/bbsPlus');  // Import signVCVP from bbsPlus.js
const { generateUID } = require('../../uidGenerator');  // Import the UID generator

async function createVC(holderDid, issuerDid, claims, keyPair) {
  try {
    
    // Generate unique ID for the VC
    const vcId = generateUID();
    console.log("Generated VC ID:", vcId);  // Log the generated VC ID

    // Directly pass claims to signVCVP
    const signature = await signVCVP(claims, keyPair);
    console.log("Signature (Base64):", signature);  // Log the signature

    // Proof is not needed in vc only signature is enough
    // Directly pass the processed claims to signVCVP
    // const resultProof= await generateBBSProof(signature.signature, keyPair.publicKey, claims);
    // const bbsProof= resultProof.proof;
    // const nonce = resultProof.nonce;
    //console.log("inside vpGeneration bbsProof Object:", bbsProof);  // Log the signature

    // Create the Verifiable Credential (VC) object
    const vc = {
      "@context": "https://www.w3.org/2018/credentials/v1",
      "type": "VerifiableCredential",
      "id": vcId,  // Add unique ID for the VC
      "issuer": issuerDid,
      "issuanceDate": new Date().toISOString(),
      "credentialSubject": {
        "id": holderDid,
        "claims": claims  // Use the claims directly
      },
      "proof": {
        "type": "BBS+Signature2021",
        "created": new Date().toISOString(),
        "proofPurpose": "assertionMethod",
        "verificationMethod": `${issuerDid}#keys-1`,
        "jws": signature,  // Include the BBS+ signature
        "publicKey": keyPair.publicKey,
      }
    };

    return vc;

  } catch (error) {
    console.error("Error creating VC:", error);
    throw error;
  }
}

// Ensure createVC is exported correctly
module.exports = { createVC };
