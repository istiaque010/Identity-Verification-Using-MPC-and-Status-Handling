const { signVCVP, generateBBSProof } = require('../crypto/bbsPlus');  // Import signVCVP from bbsPlus.js
const readlineSync = require('readline-sync');

async function selectClaims(holderDid, wallet) {
  const vcs = wallet.getVCs();  // Get all VCs for the specified holder DID
  const selectedClaims = [];
  const vcsInfo = [];

  console.log(`Available VCs for holder DID: ${holderDid}\n`);

  for (let i = 0; i < vcs.length; i++) {
    const vc = vcs[i];
    console.log(`VC ${i + 1}: Issuer ${vc.issuer}`);

    // Show claims for the VC before asking for selection
    const claims = vc.credentialSubject.claims;  // Assuming claims are stored under credentialSubject.claims
    console.log(`Claims for VC from issuer ${vc.issuer}:`);
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


      //get signature from vc

      const signature= vc.proof.jws.signature;


      
      //Now need to generate proof and save nonce for that vc
      const resultProof= await generateBBSProof(signature, keyPair.publicKey, claims, revealedIndexes);
      const bbsProof= resultProof.proof;
      const nonce = resultProof.nonce;

      // Collect the selected claims, grouped by VC
      selectedIndexes.forEach(idx => {
        if (claims[idx]) {
          selectedClaims.push({
            id: vc.id,
            vcIssuer: vc.issuer,
            claimKey: claims[idx].key,
            claimValue: claims[idx].value,
          });

        // Check if the vc.id is already in the vcsInfo array before pushing
        const isExistingVC = vcsInfo.some(info => info.id === vc.id);
        if (!isExistingVC) {
             // Add VC info (id, issuer DID, and JWS signature) if not already added
             vcsInfo.push({
               id: vc.id,
               issuerDid: vc.issuer,
               jws: vc.proof.jws, // Assuming the JWS signature is located here
               bbsProof:bbsProof,
               nonce:nonce
             });
           }

        } else {
          console.log('Invalid index, skipping...');
        }
      });


      console.log("Info about seleted claims  VCs: ", vcsInfo);

      // Output selected claims for this VC
      console.log("Selected claims for disclosure:");
      selectedIndexes.forEach(idx => {
        if (claims[idx]) {
          console.log(`${idx}: Issuer: ${vc.issuer}, Claim: ${claims[idx].key} - ${claims[idx].value}`);
        }
      });
    } else {
      console.log("Skipping this VC...\n");
    }
  }

  // Output all selected claims after processing all VCs
  console.log("\nSelected claims for disclosure:");
  selectedClaims.forEach((claim, index) => {
    console.log(`${index + 1}: Issuer: ${claim.vcIssuer}, Claim: ${claim.claimKey} - ${claim.claimValue}`);
  });

  //return selectedClaims;  // Return the selected claims along with their associated VC issuer

  return { selectedClaims, vcsInfo };  // Return both the selected claims and the corresponding VC info
}

module.exports = { selectClaims };
