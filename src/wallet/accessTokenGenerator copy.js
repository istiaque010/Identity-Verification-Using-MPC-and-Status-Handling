const readlineSync = require('readline-sync');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid'); // For generating unique IDs

// Function to generate a unique access token for a verifier based on VP ID
async function generateAccessToken(holderDid, verifierDid, vpId, wallet, privateKey) {
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
  const expirationDate = new Date();
  expirationDate.setFullYear(expirationDate.getFullYear() + 1);  // Set expiration date (1 year from now)

  // Retrieve the VP matching the given vpId
  const vp = wallet.getVPs().find(vp => vp.id === vpId);
  if (!vp) {
    throw new Error(`VP with ID ${vpId} not found in wallet.`);
  }

  // Log the structure of the VP to debug
  console.log("Verifiable Presentation structure:", JSON.stringify(vp, null, 2));

//   // Extract the claims from the VP (e.g., claims are part of `verifiableCredential`)
//   const claimsWithVCs = vp.verifiableCredential.map((vc, index) => {
//     return {
//       vcIssuer: vc.issuer,
//       claims: vc.credentialSubject.claims,
//     };
//   });

//   if (!claimsWithVCs || claimsWithVCs.length === 0) {
//     throw new Error("No claims found in the selected VP.");
//   }

  

//   // Dynamically select claims to disclose from the VP
//   console.log(`Claims available in VP (ID: ${vpId}):`);
//   let claimCounter = 0;
//   claimsWithVCs.forEach((vcData, vcIndex) => {
//     console.log(`VC ${vcIndex + 1} (Issuer: ${vcData.vcIssuer}):`);
//     vcData.claims.forEach((claim, claimIndex) => {
//       console.log(`${claimCounter}: ${claim.key}: ${claim.value}`);
//       claimCounter++;
//     });
//   });

//   const selectedClaimIndexes = readlineSync.question(
//     `Enter the indexes of the claims to disclose (comma-separated): `
//   );

//   const selectedIndexes = selectedClaimIndexes.split(',').map(idx => parseInt(idx.trim()));

//   // Collect selected claims
//   const selectedClaims = [];
//   selectedIndexes.forEach(idx => {
//     const claimData = claimsWithVCs.find(vcData => {
//       const claim = vcData.claims.find((claim, claimIndex) => claimCounter++ === idx);
//       return claim;
//     });
//     if (claimData) {
//       selectedClaims.push(claimData);
//     }
//   });

//   if (selectedClaims.length === 0) {
//     throw new Error("No valid claims selected.");
//   }

//   // Payload for the JWT
//   const payload = {
//     sub: holderDid, // Holder DID (subject)
//     verifier: verifierDid, // Verifier DID
//     vp_id: vpId, // VP identifier
//     claims: selectedClaims, // Selected claims to disclose
//     expiration: expirationDate.toISOString(), // Expiration date for the token
//     jti: tokenId, // Unique token ID
//   };

//   // Sign the JWT with the private key
//   const accessToken = jwt.sign(payload, privateKey, { algorithm: 'RS256' });

//   console.log("Generated Access Token:", accessToken);

const accessToken=1;
  return accessToken;
}

module.exports = { generateAccessToken };
