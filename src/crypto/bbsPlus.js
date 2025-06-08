const {
    generateBls12381G2KeyPair,
    blsSign,
    blsVerify,
    blsCreateProof,
    blsVerifyProof,
  } = require('@mattrglobal/bbs-signatures');  // Use require instead of import "@mattrglobal/bbs-signatures";
  
  const readlineSync = require('readline-sync');  // Used to prompt user for input

// Function to generate a BBS+ key pair (public and private keys)
async function generateBBSKeyPair() {
  try {
    // Generate the key pair using BLS12-381 curve
    console.log("Generating key pair...");
    // Generate a new key pair
    const keyPair = await generateBls12381G2KeyPair();
    console.log("Key Pair generated:", keyPair);  // Log the generated key pair

    return { keyPair };
  } catch (error) {
    console.error("Error generating BBS+ key pair: ", error);
    throw error;
  }
}

// Function to sign a message (VC or VP) using the private key
async function signVCVP(claims, keyPair) {

    console.log("Claims to be signed:", claims);  // Log the messages (with keys and values)

   // Convert messages to Uint8Array format for signing
  const claimsToSign = claims.map(msg => Uint8Array.from(Buffer.from(msg.value, "utf-8")));

  // Create the signature
  console.log("Signing messages...");
  const signature = await blsSign({
    keyPair,
    messages: claimsToSign,
  });
  console.log("Signature (Base64):", Buffer.from(signature).toString('base64'));  // Log the signature

  return { signature };
 
}

// Function to verify the BBS+ signature of a message (VC or VP)
async function verifyVCVP(claims, signature, publicKey) {


  console.log("Claims to be signed:", claims);  // Log the messages (with keys and values)

   // Convert messages to Uint8Array format for signing
   //const claimsToSign = claims.map(msg => Uint8Array.from(Buffer.from(msg.value, "utf-8")));

   // Convert messages to Uint8Array format for signing
   const claimsToSign = claims.map(msg => {
    if (typeof msg.value !== 'string') {
        console.error("Invalid claim value:", msg.value);  // Log invalid claim values for debugging
        return null; // Return null for invalid claim values
    }
    // Convert valid claim values to Uint8Array
    return Uint8Array.from(Buffer.from(msg.value, "utf-8"));
}).filter(item => item !== null);  // Filter out invalid claims (null values)


// If the signature is not a Uint8Array, convert it.
const signatureToVerify = Uint8Array.from(Object.values(signature));

console.log("Processed signature for verifying:", signatureToVerify);

   console.log("Processed claims for verifying:", claimsToSign);  // Debugging the processed claims
   console.log("Processed publicKey for verifying:", publicKey);  // Debugging the processed publicKey
   console.log("Processed signature for verifying:", signature);  // Debugging the processed signature

   console.log("Processed signatureToVerify for verifying:", signatureToVerify);  // Debugging the processed signatureToVerify
  
  // Verify the signature
  console.log("Verifying signature...");
  const isVerified = await blsVerify({
    publicKey: publicKey,
    messages: claimsToSign,
    signature: signatureToVerify,  // Pass the signature as a Uint8Array
  });
  console.log("Signature Verified:", isVerified);  // Log the result of signature verification
  return isVerified;
 
}

// Function to generate a BBS+ proof for the selected claims
async function generateBBSProof(signature, publicKey, claims, revealedIndexes) {
  try {
      
    console.log("Inside bbsPlus: Generating proof...:");

    // Generate a unique nonce for each proof (you can also pass a different nonce if needed)
    const nonce = Uint8Array.from(Buffer.from(Date.now().toString(), "utf8"));

    console.log("Inside Generating Proof signature:",signature);
    console.log("Inside Generating Proof publicKey:", publicKey);
    console.log("Inside Generating Proof claims:", claims);
    console.log("Inside Generating Proof revealedIndexes:", revealedIndexes);
    console.log("Inside Generating Proof nonce:", nonce);

    // Preprocess claims into the correct format for signing
    const claimsToSign = claims.map(claim => Uint8Array.from(Buffer.from(claim.value, "utf-8")));
  
    // Now create the proof using all the claims
    console.log("Creating proof for all disclosed messages...");
    const proof = await blsCreateProof({
      signature,  // The signature to verify the claims
      publicKey,  // Public key of the holder
      messages: claimsToSign,  // All claims are being disclosed (processed as Uint8Array)
      nonce,  // The unique nonce used for this proof
      revealed: revealedIndexes,  
    });

    console.log("Proof Object:", proof);
    console.log("Proof Object (Base64):", Buffer.from(proof).toString('base64'));  // Base64 encoding of the proof

    // Return both the proof and the nonce for later use
    return { proof, nonce };

  } catch (error) {
    console.error("Error creating BBS+ proof:", error);
    throw error;
  }

}

// Function to verify the BBS+ proof of the disclosed claims one by one

// Function to verify the BBS+ proof of the disclosed claims
async function verifyBBSProof( bbsProof, nonce, issuerPubKey, selectedClaims, revealedIndexes ) {
  console.log("Verifying proof...");


    // Ensure nonce is a Uint8Array (if it's not already)
    //const nonceToVerify = Uint8Array.from(Buffer.from(nonce, "utf8"));

     console.log("Inside verifyBBSProof  bbsProof:", bbsProof);
     console.log("Inside verifyBBSProof  bbsProof:", bbsProof);
     console.log("Inside verifyBBSProof  issuerPubKey:", issuerPubKey);
     console.log("Inside verifyBBSProof  selectedClaims:", selectedClaims);
     console.log("Inside verifyBBSProof  revealedIndexes:", revealedIndexes);


  // Ensure revealedMessages are converted to Uint8Array
  const messagesToVerify = selectedClaims.map(msg => Uint8Array.from(Buffer.from(msg.value, "utf-8")));

  // Ensure nonce is a Uint8Array (if it's not already)
  const nonceToVerify = new Uint8Array(Object.values(nonce)); // Convert nonce object to Uint8Array

  // If the proof is not already a Uint8Array, convert it
  const proofToVerify = Uint8Array.from(Object.values(bbsProof));  // Convert proof if it is not Uint8Array


  // Verify the proof
  const isProofVerified = await blsVerifyProof({
    proof: proofToVerify,
    publicKey: issuerPubKey,
    messages: messagesToVerify,  // Verify the disclosed messages
    nonce: nonceToVerify // The same nonce used in proof creation
  });

  //const isProofVerified= true;

  console.log("Proof Verified:", isProofVerified);  // Log the result of proof verification
  return isProofVerified;
}



module.exports = { generateBBSKeyPair, signVCVP, verifyVCVP, generateBBSProof, verifyBBSProof};
