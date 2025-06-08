const { signVCVP, generateBBSProof } = require('../crypto/bbsPlus');  // Import signVCVP from bbsPlus.js
const readlineSync = require('readline-sync');

async function selectClaims(holderDid, wallet, keyPair) {
  const vcs = wallet.getVCs();  // Get all VCs for the specified holder DID
  const vcsInfo = [];  // Store proofs, nonces, and selected claims for each VC

  console.log(`Available VCs claims for holder DID: ${holderDid}\n`);

  for (let i = 0; i < vcs.length; i++) {
    const vc = vcs[i];

    console.log("Inside selected Claims: vc.id: ",vc.id);
    //console.log("Inside selected Claims: claims: ",vc.credentialSubject.claims);

    // Show claims for the VC before asking for selection
    const claims = vc.credentialSubject.claims;  // Assuming claims are stored under credentialSubject.claims

    claims.forEach((claim, index) => {
      console.log(`${index}: ${claim.key} - ${claim.value}`);
    });
  
    // Ask user if they want to include this VC for claims disclosure
    const includeVC = readlineSync.question(`Do you want to include this VC for claims disclosure? (Yes=1, No=0): `);

    // Only proceed if user wants to include this VC
    if (includeVC === '1') {
      // Prompt the user to select the indexes of claims to disclose
      const claimIndexes = readlineSync.question(
        `Enter the indexes of the claims to disclose (comma-separated): `
      );

      // Convert input into an array of claim indexes
      const selectedIndexes = claimIndexes.split(',').map(idx => parseInt(idx.trim()));

      // Select the claims based on the selected indexes for this VC
      const selectedClaimsForVC = selectedIndexes.map(idx => claims[idx]).filter(Boolean);
      
      // Get the signature from vc
      const signature = vc.proof.jws.signature;

        // Generate proof for selected claims of this VC only
        const revealedIndexes = selectedIndexes;  // Use the selectedIndexes as revealed indexes
    
      // //print and check the format
      // console.log("Inside select Claims: vc.issuer: ",vc.issuer);
      // console.log("Inside select Claims: signature: ",signature);
      // console.log("Inside select Claims: Holder keyPair.publicKey: ",keyPair.publicKey);
      // console.log("Inside select Claims: claims: ",claims);
      // console.log("Inside select Claims: revealedIndexes: ",revealedIndexes);
      // console.log("Inside select Claims: selectedClaimsForVC: ",selectedClaimsForVC);

  
    //at generating proof the public key would be the public key of VC issuer, which signature you are using
    const vcIssuerPubKey= vc.proof.publicKey;
  
      const resultProof = await generateBBSProof(signature, vcIssuerPubKey, claims, revealedIndexes);
      const bbsProof = resultProof.proof;
      const nonce = resultProof.nonce;

      // Store VC info (id, issuer DID, JWS signature, proof, and selected claims) in vcsInfo
      vcsInfo.push({
        id: vc.id,
        issuerDid: vc.issuer,
        issuerPubKey: vcIssuerPubKey,
        jws: signature, // Assuming the JWS signature is located here of vc issuer
        bbsProof: bbsProof,
        nonce: nonce,
        revealedIndexes:revealedIndexes,
        selectedClaims: selectedClaimsForVC  // Store only the selected claims for this VC
      });

      console.log("Info about selected vc all info and claims in VCs: ", vcsInfo);

    } else {
      console.log("Skipping this VC...\n");
    }
  }

  // Output all VCs info after processing all VCs
  console.log("\nVC info with proofs:");
  vcsInfo.forEach((vcInfo, index) => {
    console.log(`${index}: VC ID: ${vcInfo.id}, Issuer: ${vcInfo.issuerDid}, Nonce: ${vcInfo.nonce}`);
  });

  return vcsInfo;  // Return the vcsInfo which contains proof and nonce for each VC, along with selected claims
}

module.exports = { selectClaims};
