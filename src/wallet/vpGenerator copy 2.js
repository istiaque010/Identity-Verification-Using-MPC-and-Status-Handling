const { signVCVP, generateBBSProof } = require('../crypto/bbsPlus');  // Import signVCVP from bbsPlus.js
const { generateUID } = require('../../uidGenerator');  // Import the UID generator

async function createVP(holderDid, selectedClaims, vcsInfo, keyPair) {
  try {


    // Generate unique ID for the Vp
    const vpId = generateUID();
    console.log("Generated VP ID:", vpId);  // Log the generated VC ID


    console.log("Selected Claims which is comimg inside the VP:", selectedClaims);  // selectedClaims from this later we prepare claimsToSign but for tracking it is important

    // Preprocess selectedClaims into the correct format for signing
    const claimsToSign = selectedClaims.map(claim => {
      return {
        key: claim.claimKey,  // Use 'claimKey' from the selected claims
        value: claim.claimValue // Use 'claimValue' from the selected claims
      };
    });


    // Directly pass the processed claims to signVCVP
    const signature = await signVCVP(claimsToSign, keyPair);
    console.log("Signature (Base64):", signature);  // Log the signature

    
    // Directly pass the processed claims to signVCVP
    const resultProof= await generateBBSProof(signature.signature, keyPair.publicKey, claimsToSign);

    const bbsProof= resultProof.proof;
    const nonce = resultProof.nonce;
    console.log("inside vpGeneration bbsProof Object:", bbsProof);  // Log the signature
  

    // Create the Verifiable Presentation (VP) object
    const vp = {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "type": "VerifiablePresentation",
      "id": vpId,  // Add unique ID for the Vp
      "holder": holderDid,
      "verifiableCredential": selectedClaims,//se the SelectedClaims no processed
      //erifiableCredential": claimsToSign,  // Use the only signed formatted claims
      "proof": {
        "type": "BBS+Signature2021",
        "created": new Date().toISOString(),
        "proofPurpose": "authentication",  // Use "authentication" for VP purpose
        "verificationMethod": `Logic would be set later#keys-1`,
        "challenge": "12345678-abcd-efgh-ijkl-1234567890ab",  // Random challenge (you can modify it)
        "domain": "example.com",  // Random example domain
        "jws": signature,  // The JWS token (signed claims)
        "bbsProof": bbsProof,  // The proof of claims
        "nonce":nonce

      },
      "vcsInfo": vcsInfo
    };

    return vp;

  } catch (error) {
    console.error("Error creating VP:", error);
    throw error;
  }
}

// Ensure createVP is exported correctly
module.exports = { createVP };
