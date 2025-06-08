const readlineSync = require('readline-sync');

async function selectClaims(holderDid, wallet) {
  const vcs = wallet.getVCs();  // Get all VCs for the specified holder DID
  const selectedClaims = [];

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

      // Collect the selected claims, grouped by VC
      selectedIndexes.forEach(idx => {
        if (claims[idx]) {
          selectedClaims.push({
            vcIssuer: vc.issuer,
            claimKey: claims[idx].key,
            claimValue: claims[idx].value,
          });
        } else {
          console.log('Invalid index, skipping...');
        }
      });

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

  return selectedClaims;  // Return the selected claims along with their associated VC issuer
}

module.exports = { selectClaims };
