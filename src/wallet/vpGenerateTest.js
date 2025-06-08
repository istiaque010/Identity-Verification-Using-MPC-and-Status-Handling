const { signVCVP, generateBBSProof } = require('../crypto/bbsPlus'); // Import signVCVP from bbsPlus.js

// Function to generate the Verifiable Presentation (VP)
async function generateVP(holderDid, vcsInfo, keyPair) {
  try {
    console.log(`Generating Verifiable Presentation (VP) for holder DID: ${holderDid}`);
    
    const vpId = `vp-${Date.now()}`; // Unique ID for the VP (you can generate it differently as needed)
    const selectedClaims = [];
    
    // Loop through the vcsInfo and add claims to the VP
    for (const vcInfo of vcsInfo) {
      const { id, issuerDid, bbsProof, nonce, selectedClaims: claims } = vcInfo;
      
      // Add the claims of this VC to the selectedClaims array
      selectedClaims.push(...claims);
      
      // The proof for this VC in the VP
      const vpProof = {
        type: "BBS+Signature2021",
        created: new Date().toISOString(),
        proofPurpose: "authentication", // Use "authentication" for VP purpose
        verificationMethod: `${issuerDid}#keys-1`,
        challenge: "random-challenge", // Use a random challenge here
        domain: "example.com", // Use a domain (e.g., example.com)
        jws: vcInfo.jws,  // The JWS signature for this VC
        bbsProof: bbsProof,  // BBS+ proof for the selected claims
      };
      
      // Add the proof to the VP
      const vp = {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://www.w3.org/2018/credentials/examples/v1",
        ],
        "type": "VerifiablePresentation",
        "id": vpId,  // Unique VP ID
        "holder": holderDid, // The holder's DID
        "verifiableCredential": [{
          id: id,  // The ID of the VC
          issuer: issuerDid, // The issuer DID
          credentialSubject: {
            id: holderDid,
            claims: selectedClaims,  // Add the selected claims from vcsInfo
          },
          proof: vpProof  // Include the proof generated above
        }],
      };
      
      console.log("Generated VP:", vp);

      return vp;  // Return the VP for use

    }
  } catch (error) {
    console.error("Error generating Verifiable Presentation (VP):", error);
    throw error;
  }
}

module.exports = { generateVP };
