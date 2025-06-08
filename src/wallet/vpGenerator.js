const { signVCVP, generateBBSProof } = require('../crypto/bbsPlus');  // Import signVCVP from bbsPlus.js
const { generateUID } = require('../../uidGenerator');  // Import the UID generator

// Function to generate the Verifiable Presentation (VP)
async function createVP(holderDid, vcsInfo, keyPair) {
  try {

    console.log(`Generating Verifiable Presentation (VP) for holder DID: ${holderDid}`);

    const vpId = generateUID(); // Unique ID for the VP (you can generate it differently as needed)
    const selectedClaims = [];

    // Collect all selected claims from vcsInfo
    vcsInfo.forEach(vcInfo => {
      selectedClaims.push(...vcInfo.selectedClaims);
    });

    console.log("Inside vpGenerator  selectedClaims:", selectedClaims);

    // Now, we generate claimsToSign from the selected claims gathered from all VCs
    const claimsToSign = selectedClaims.map(claim => {
      return {
        key: claim.key,  // Use 'claimKey' from the selected claims
        value: claim.value // Use 'claimValue' from the selected claims
      };
    });

    console.log("Claims to sign:", claimsToSign);

    // Directly pass the processed claims to signVCVP
    const signature = await signVCVP(claimsToSign, keyPair);
    console.log("Signature (Base64):", signature);  // Log the signature

    // Generate proof for the selected claims of the entire VP (not for each VC)
    const revealedIndexes = claimsToSign.map((_, index) => index);  // Use the sequential indexes of claimsToSign
    const resultProof = await generateBBSProof(signature.signature, keyPair.publicKey, claimsToSign, revealedIndexes);
    const bbsProof = resultProof.proof;
    const nonce = resultProof.nonce;
    console.log("Generated BBS+ proof for VP:", bbsProof);  // Log the proof

    // Create the Verifiable Presentation (VP) object
    const vp = {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "type": "VerifiablePresentation",
      "id": vpId,  // Add unique ID for the Vp
      "holder": holderDid,
      "verifiableCredential": vcsInfo,  // Inside this vcsInfo there are all selected claims
      "proof": {
        "type": "BBS+Signature2021",
        "created": new Date().toISOString(),
        "proofPurpose": "authentication",  // Use "authentication" for VP purpose
        "verificationMethod": `Logic would be set later#keys-1`,
        "challenge": generateUID(),  // Random challenge (use the UID generator here)
        "domain": "example.com",  // Random example domain
        "jws": signature,  // The JWS token (signed claims)
        "bbsProof": bbsProof,  // The proof of claims
        "nonce": nonce,
        "revealedIndexes":revealedIndexes
      }
    };

    return vp;  // Return the VP for use

  } catch (error) {
    console.error("Error creating VP:", error);
    throw error;
  }
}

// Ensure createVP is exported correctly
module.exports = { createVP };
