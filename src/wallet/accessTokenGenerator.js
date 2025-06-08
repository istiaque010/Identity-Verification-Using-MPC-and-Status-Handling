const readlineSync = require('readline-sync');
const uuidv4 = require('uuid').v4;

async function generateAccessToken(holderDid, verifierDid, vpId, wallet, keyPair4) {
  console.log("Access Token Generation....");

  const accessTokenvcsInfo = [];  // Store information about selected claims for each VC
  const vp = wallet.getVPs().find(vp => vp.id === vpId); // Retrieve the VP matching the given vpId
  if (!vp) {
    throw new Error(`VP with ID ${vpId} not found in wallet.`);
  }

  // Ask the user if they want to generate the access token for the entire VP
  const includeVP = readlineSync.question(`Do you want to generate an access token for this VP: ${vpId}? (Yes=1, No=0): `);

  const expirationHours = readlineSync.questionInt("Enter the expiration time for the access token in hours: ");
  const expirationDate = new Date();
  expirationDate.setHours(expirationDate.getHours() + expirationHours);  // Set expiration date

  // Proceed if the user agrees to generate the access token for the VP
  if (includeVP === '1') {
    // Iterate over each VC in the Verifiable Presentation (VP)
    for (let i = 0; i < vp.verifiableCredential.length; i++) {
      const vcsInfo = vp.verifiableCredential[i];  // Access vcsInfo from each VC in the VP

      if (!vcsInfo) {
        console.log(`No vcsInfo found for VC with ID: ${vp.verifiableCredential[i].id}`);
        continue;
      }

      // Show claims for the vcsInfo before asking for selection
      const claims = vcsInfo.selectedClaims;  // Assuming selectedClaims are part of vcsInfo
      const claimIndexes = vcsInfo.revealedIndexes;  // Get the claim indexes from revealedIndexes
      console.log(`VC ID: ${vp.verifiableCredential[i].id}`);
      
      // Display the available claim indexes and corresponding claims using a for loop
      console.log("Available Claims (index - { key: 'claimKey', value: 'claimValue' }):");
      for (let idx = 0; idx < claimIndexes.length; idx++) {
        const claim = claims[idx];  // Get the corresponding claim based on the index
          console.log(`[ ${idx} ] - { Claim Vaqlue: '${claim.key}'  Claim Vaqlue: '${claim.value}'}' }`);
      }

      // Ask the user to select the indexes of claims to disclose
      const selectedClaimIndexes = readlineSync.question(
        `Enter the indexes of the claims to disclose from the available indexes (comma-separated): `
      );

      // Convert input into an array of selected claim indexes
      const selectedIndexes = selectedClaimIndexes.split(',').map(idx => parseInt(idx.trim()));


         // Create an array to store the values of the selected indexes (from claimIndexes)
         const claimIndexesValue = selectedIndexes
         .map(idx => claimIndexes[idx])  // Select the claims based on the corresponding indexes from claimIndexes
         .filter(Boolean);  // Filter out any invalid selections

        //console.log("Values of Selected Indexes ", claimIndexesValue);

      
      // Select the claims based on the selected indexes for this VC
      const selectedClaimsForVC = selectedIndexes
        .map(idx => claims[idx])  // Select the claims based on the corresponding indexes
        .filter(Boolean);  // Filter out any invalid selections

      // Ensure that selected claims are not empty
      if (selectedClaimsForVC.length === 0) {
        console.log(`No valid claims selected for VC with ID: ${vp.verifiableCredential[i].id}`);
        continue;
      }

      //console.log("Selected Claims: ", selectedClaimsForVC);
      //console.log("Revealed Indexes: ", selectedIndexes);

      // Store VC info (id, issuer DID, and selected claims) in accessTokenvcsInfo
      accessTokenvcsInfo.push({
        vcid: vp.verifiableCredential[i].id,  // VC ID
        issuerDid: vp.verifiableCredential[i].issuer,  // VC Issuer DID
        //revealedIndexes: selectedIndexes,  // List of indexes for the selected claims
        revealedIndexesValue: claimIndexesValue,
        selectedClaims: selectedClaimsForVC  // Store only the selected claims for this VC
      });
    }

    // After processing all VCs, prepare the access token
    const tokenId = uuidv4();  // Generate a unique token ID

    // Construct the payload for the access token
    const payload = {
      holder: holderDid,
      verifier: verifierDid,
      vp_id: vpId,
      expiration: expirationDate.toISOString(),
      jti: tokenId,
      accessTokenvcsInfo: accessTokenvcsInfo  // Include all VCs info with selected claims
    };

    //Sign the access token payload 

    // Return the access token containing all the necessary information
    const accessToken = {
      payload: payload
    };

    console.log("Generated Access Token:");
    console.log(JSON.stringify(accessToken, null, 2));  // Log the generated access token

    return accessToken;
  } else {
    console.log("You chose not to generate an access token for this VP.");
    return null;
  }
}

module.exports = { generateAccessToken };
