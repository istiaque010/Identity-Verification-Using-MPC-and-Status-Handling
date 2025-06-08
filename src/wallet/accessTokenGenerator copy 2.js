const { v4: uuidv4 } = require('uuid'); // For generating unique IDs
const { signVCVP } = require('../crypto/bbsPlus'); // Import signVCVP (signing with BLS) from bbsPlus.js
const readlineSync = require('readline-sync');

// Function to generate a unique access token for a verifier based on VP ID
async function generateAccessToken(holderDid, verifierDid, vpId, wallet, keyPair) {
  // Ask the holder for approval before proceeding
  const approval = readlineSync.question(
    `Access request from Verifier: ${verifierDid}. Do you approve? (Yes=1, No=0): `
  );

  // If the holder denies, exit the function
  if (approval !== '1') {
    console.log("Access request denied. Exiting...");
    return;
  }

  const tokenId = uuidv4();  // Generate a unique token ID
 

   // Ask the holder for the expiration time in hours
   const expirationHours = readlineSync.questionInt(
    "Enter the expiration time for the access token in hours: "
  );

  if (isNaN(expirationHours) || expirationHours <= 0) {
    console.log("Invalid expiration time. Please enter a positive number.");
    return;
  }

  const expirationDate = new Date();
  expirationDate.setHours(expirationDate.getHours() + expirationHours);  // Set expiration date (from current time)

  // Retrieve the VP matching the given vpId
  const vp = wallet.getVPs().find(vp => vp.id === vpId);
  if (!vp) {
    throw new Error(`VP with ID ${vpId} not found in wallet.`);
  }

  // Extract the claims from the VP (e.g., claims are part of `verifiableCredential`)
  let claims = vp.verifiableCredential;

  console.log("Claims format in VP : ", claims);


  if (!claims || claims.length === 0) {
    throw new Error("No claims found in the selected VP.");
  }

  // Preprocess claims to match the expected format
  console.log(`Claims available in VP (ID: ${vpId}):`);
  claims = claims.flat().map(claim => ({
    key: claim.key || claim.claimKey,    // Ensure 'key' is consistent in format
    value: claim.value || claim.claimValue // Ensure 'value' is consistent in format
  }));

  // Log claims for verification
  claims.forEach((claim, index) => {
    console.log(`${index}: ${claim.key}: ${claim.value}`);
  });

  const selectedClaimIndexes = readlineSync.question(
    `Enter the indexes of the claims to disclose (comma-separated): `
  );

  const selectedIndexes = selectedClaimIndexes.split(',').map(idx => parseInt(idx.trim()));

  // Collect selected claims
  const selectedClaims = selectedIndexes.map(idx => claims[idx]).filter(Boolean);

  if (selectedClaims.length === 0) {
    throw new Error("No valid claims selected.");
  }

  // Preprocess selectedClaims into the correct format for signing
  const claimsToSign = selectedClaims.map(claim => {
    return {
      key: claim.key,  // Use 'claimKey' from the selected claims
      value: claim.value // Use 'claimValue' from the selected claims
    };
  });


// Preprocess selectedClaims to only extract the 'key'
const keysToSign = selectedClaims.map(claim => claim.key);

// Log the keys to verify
console.log("Keys to be signed:", keysToSign);




  // Log the claims to be signed for verification
  console.log("Claims to be signed:", JSON.stringify(claimsToSign, null, 2));

  // Sign the claims using the BLS private key (from generateBls12381G2KeyPair)
  const signature = await signVCVP(claimsToSign, keyPair);
  console.log("Generated Access Token Signature:", signature);

  // Payload for the JWT (you can format this as a JWT-like object)
  const payload = {
    holder: holderDid, // Holder DID (subject)
    verifier: verifierDid, // Verifier DID
    vp_id: vpId, // VP identifier
    selectedIndexes: selectedIndexes, // Store selected claim indexes
    //claims: JSON.stringify(claimsToSign), // Selected claims to disclose (convert to string)
    claims: JSON.stringify(keysToSign), // Selected claims to disclose (convert to string)
    expiration: expirationDate.toISOString(), // Expiration date for the token
    jti: tokenId, // Unique token ID
  };

  // Return the access token (in this case, it could just be the payload and the signature)
  const accessToken = {
    payload: payload,
    signature: signature
  };

  console.log("Generated Access Token:");
  console.log(JSON.stringify(accessToken, null, 2));  // Properly log the access token

  return accessToken;
}

module.exports = { generateAccessToken };
