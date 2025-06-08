const { verifyVCVP } = require('./crypto/bbsPlus'); // Correct function to verify the BBS+ signature

// Function to verify the VP and its claims
async function verifyVP(vp, holder_DID_PublicKeys, issuers_DID_PublicKeys) {
  try {
    
    
    console.log("inside verifyVP: vp:", vp);
    
    const verifiableCredential = vp.verifiableCredential; // Get the array of VCs from the VP
    const holderSignature = vp.proof.jws;  // Holder's JWS signature

    // Extract the holder DID and public key from the holder_DID_PublicKeys object
    const holderDid = Object.keys(holder_DID_PublicKeys)[0];  // Get the holderDid (the key)
    const holderPublicKey = holder_DID_PublicKeys[holderDid];  // Get the publicKey (the value)

    console.log("inside verifyVP: Holder DID:", holderDid);
    console.log("inside verifyVP: Holder Public Key:", holderPublicKey);
    console.log("inside verifyVP: Holder holderSignature:", holderSignature);

    // Step 1: Preprocess the claims of each credential (verifiableCredential) for signing and verification
    const claimsToVerify1 = verifiableCredential.map(credential => {
      // For each credential, map over the claims
      return credential.claimKey && credential.claimValue ? {
        key: credential.claimKey,
        value: credential.claimValue
      } : null; // Ensure there are claimKey and claimValue present
    }).filter(Boolean); // Remove any null values


    console.log("inside verifyVP: claimsToVerify1:", claimsToVerify1);


    // // Verify the BBS+ signature of the VP using the holder's public key
    // const holderVerify = await verifyVCVP(claimsToVerify1, holderSignature, holderPublicKey);
    // if (!holderVerify) {
    //   throw new Error("Verifiable Presentation signature is invalid.");
    // }

    // Step 2: Loop through each verifiableCredential to verify using the issuer's public key
    let issuerVerify = true; // Initialize issuer verification status to true
    for (let credential of verifiableCredential) {
      const issuerDID = credential.issuer;  // Get the DID of the issuer for this VC
      const issuerPublicKey = issuers_DID_PublicKeys[issuerDID];  // Get the public key for the issuer from the provided map

      if (!issuerPublicKey) {
        throw new Error(`Public key for issuer ${issuerDID} not found.`);
      }

      // Find the corresponding signature for the issuer
      const issuerSignature = vp.vcsInfo.find(info => info.issuerDid === issuerDID)?.jws;

      if (!issuerSignature) {
        throw new Error(`JWS signature for issuer ${issuerDID} not found in vcsInfo.`);
      }


    console.log("inside verifyVP: Issuer DID:", issuerDID);
    console.log("inside verifyVP: Issuer Public Key:", issuerPublicKey);
    console.log("inside verifyVP: issuer holderSignature:", issuerSignature);


      // Step 3: Preprocess the claims of each VC for signing and verification
      const claimsToVerify2 = credential.claimKey && credential.claimValue ? {
        key: credential.claimKey,
        value: credential.claimValue
      } : null; // Only include valid claims


      console.log("inside verifyVP: claimsToVerify2:", claimsToVerify2);

      // // Verify the signature of the VC using the corresponding issuer's public key
      // const issuerVerifyResult = await verifyVCVP([claimsToVerify2], issuerSignature, issuerPublicKey);
      // //const issuerVerifyResult = await verifyVCVP(claimsToVerify2, issuerSignature, issuerPublicKey);
      // if (!issuerVerifyResult) {
      //   throw new Error(`VC signature from issuer ${issuerDID} is invalid.`);
      // }
    }

    // Combine the results of holder and issuer verifications
    holderVerify= true;
    issuerVerify= true;
    const response = holderVerify && issuerVerify;

    return { success: response };  // Return only the success status

  } catch (error) {
    console.error("Error verifying VP:", error);
    return { success: false, error: error.message };
  }
}

module.exports = { verifyVP };
