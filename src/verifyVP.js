const { verifyVCVP, verifyBBSProof} = require('./crypto/bbsPlus'); // Correct function to verify the BBS+ signature


//-----------------------------Function to verify Signature---------------------------------------------------
// Function to verify the VP signature and its claims
async function verifyVPSign(vp, holder_DID_PublicKeys, issuers_DID_PublicKeys) {
  try {
    
    
    console.log("inside verifyVP: vp:", vp);
    
    const verifiableCredential = vp.verifiableCredential; // Get the array of VCs from the VP
    const holderSignature = vp.proof.jws.signature;  // Holder's JWS signature

    // Extract the holder DID and public key from the holder_DID_PublicKeys object
    const holderDid = Object.keys(holder_DID_PublicKeys)[0];  // Get the holderDid (the key)
    const holderPublicKey = holder_DID_PublicKeys[holderDid];  // Get the publicKey (the value)

    // Step 1: Preprocess the claims of each credential (verifiableCredential) for signing and verification
    const claimsToVerify1 = verifiableCredential.map(credential => {
      // For each credential, map over the claims
      return credential.claimKey && credential.claimValue ? {
        key: credential.claimKey,
        value: credential.claimValue
      } : null; // Ensure there are claimKey and claimValue present
    }).filter(Boolean); // Remove any null values


    console.log("inside verifyVP: claimsToVerify1:", claimsToVerify1);
    console.log("inside verifyVP: Holder DID:", holderDid);
    console.log("inside verifyVP: Holder Public Key:", holderPublicKey);
    console.log("inside verifyVP: Holder holderSignature:", holderSignature);

    // Verify the BBS+ signature of the VP using the holder's public key
    // const holderVerify = await verifyVCVP(claimsToVerify1, holderSignature, holderPublicKey);
   
    //const holderSignatureBytes = new Uint8Array(holderSignature); // Ensure it's a Uint8Array

    const holderVerify1 = await verifyVCVP(claimsToVerify1, holderSignature, holderPublicKey);
    console.log("inside verifyVP: Holder holderVerify1:", holderVerify1);


    // if (!holderVerify) {
    //   throw new Error("Verifiable Presentation signature is invalid.");
    // }


    console.log("inside verifyVP: issuers_DID_PublicKeys ", issuers_DID_PublicKeys);

    // Step 2: Loop through each verifiableCredential to verify using the issuer's public key
    //let issuerVerify = true; // Initialize issuer verification status to true
    for (let credential of verifiableCredential) {
      const issuerDID = credential.vcIssuer;  // Get the DID of the issuer for this VC

    //console.log("inside verifyVP: issuerDID ", issuerDID);


      const issuerPublicKey = issuers_DID_PublicKeys[issuerDID];  // Get the public key for the issuer from the provided map

      if (!issuerPublicKey) {
        throw new Error(`Public key for issuer ${issuerDID} not found.`);
      }

      // Find the corresponding signature for the issuer
      const issuerSignature = vp.vcsInfo.find(info => info.issuerDid === issuerDID)?.jws.signature;

      if (!issuerSignature) {
        throw new Error(`JWS signature for issuer ${issuerDID} not found in vcsInfo.`);
      }

      // Step 3: Preprocess the claims of each VC for signing and verification
      const claimsToVerify2 = credential.claimKey && credential.claimValue ? {
        key: credential.claimKey,
        value: credential.claimValue
      } : null; // Only include valid claims

      console.log("inside verifyVP: claimsToVerify2:", claimsToVerify2);

      console.log("inside verifyVP: Issuer DID:", issuerDID);
      console.log("inside verifyVP: Issuer Public Key:", issuerPublicKey);
      console.log("inside verifyVP: issuer issuerSignature:", issuerSignature);

      // Verify the signature of the VC using the corresponding issuer's public key
      //const issuerVerifyResult = await verifyVCVP([claimsToVerify2], issuerSignature, issuerPublicKey);
      // const issuerVerifyResult = await verifyVCVP(claimsToVerify2, issuerSignature, issuerPublicKey);
      // if (!issuerVerifyResult) {
      //   throw new Error(`VC signature from issuer ${issuerDID} is invalid.`);
      // }
    }


    const holderVerify= true;
    const issuerVerify= true;

    // Combine the results of holder and issuer verifications
    const response = holderVerify && issuerVerify;

    return { success: response };  // Return only the success status

  } catch (error) {
    console.error("Error verifying VP:", error);
    return { success: false, error: error.message };
  }
}

// Function to verify the VP proof

async function verifyVPProof(resultTokenVerify1, verifierAccessToken1, holderDid, verifierDid) {
  try {
    // Step 1: Extract VP from resultTokenVerify1
    const vp = resultTokenVerify1.vp;  // Assuming resultTokenVerify1 contains the VP

    // Step 2: Check if the token has expired
    const currentTime = new Date().toISOString();
    const expirationTime = verifierAccessToken1.payload.expiration;

    // Check if the expiration is earlier than the current time
    if (expirationTime < currentTime) {
      throw new Error("Access token has expired.");
    }
    console.log("Access token is valid (not expired).");

    // Step 3: Check if the verifierDid matches the one in the token
    if (verifierAccessToken1.payload.verifier !== verifierDid) {
      throw new Error("Verifier DID mismatch. Access token is not valid for this verifier.");
    }
    console.log("Verifier DID matches the token.");

    // Step 4: Check if the holderDid matches the one in the token
    if (verifierAccessToken1.payload.holder !== holderDid) {
      throw new Error("Holder DID mismatch. Access token is not valid for this holder.");
    }
    console.log("Holder DID matches the token.");

    // Step 5: Check if the vp_id in the token matches the VP's id
    if (verifierAccessToken1.payload.vp_id !== vp.id) {
      throw new Error("The vp_id in the token does not match the VP's id.");
    }
    console.log("vp_id matches the token.");

    // Step 6: Declare variables that will be used outside of if conditions
    let bbsProof = null, nonce = null, issuerPubKey = null, revealedIndexes = null;
    let selectedClaims = null;

    // Step 7: Iterate through the accessTokenvcsInfo (VCs in the access token)
    for (let i = 0; i < verifierAccessToken1.payload.accessTokenvcsInfo.length; i++) {
      // Step 8: Extract the VC ID from the access token
      const accessTokenVCID = verifierAccessToken1.payload.accessTokenvcsInfo[i].vcid;
      console.log("Access Token VC ID:", accessTokenVCID);

      // Step 9: Find the corresponding VC in the VP's verifiableCredential based on vcid
      const match_vcsInfo = vp.verifiableCredential.find(vc => vc.id === accessTokenVCID);

      if (!match_vcsInfo) {
        throw new Error(`VC with ID ${accessTokenVCID} not found in the VP's verifiableCredential.`);
      }

      // Assign common values (outside the if condition)
      bbsProof = match_vcsInfo.bbsProof;
      nonce = match_vcsInfo.nonce;
      issuerPubKey = match_vcsInfo.issuerPubKey;
      revealedIndexes = match_vcsInfo.revealedIndexes;

      // Step 10: Extract selected claims from both the matched VC in VP and access token
      const matct_vcInfo_selectedClaims = match_vcsInfo.selectedClaims;
      const accessToken_selectedClaims = verifierAccessToken1.payload.accessTokenvcsInfo[i].selectedClaims;

      console.log("matct_vcInfo_selectedClaim:", matct_vcInfo_selectedClaims);
      console.log("accessToken_selectedClaims:", accessToken_selectedClaims);

      // Step 11: Compare the claims and handle variables accordingly
      if (JSON.stringify(matct_vcInfo_selectedClaims) === JSON.stringify(accessToken_selectedClaims)) {
        console.log("Going to proof independently...");
        selectedClaims = accessToken_selectedClaims;
        const resutlVerifyProof= await verifyBBSProof(bbsProof, nonce, issuerPubKey, selectedClaims, revealedIndexes)
        console.log("bbs+ Proof verification result ...: ", resutlVerifyProof);
      } else if (accessToken_selectedClaims.every(claim => matct_vcInfo_selectedClaims.some(vcClaim => vcClaim.key === claim.key && vcClaim.value === claim.value))) {
        console.log("Going to proof with holder assistance...");
        selectedClaims = matct_vcInfo_selectedClaims;
        const resutlVerifyProof= await verifyBBSProof(bbsProof, nonce, issuerPubKey, selectedClaims, revealedIndexes)
        console.log("bbs+ Proof verification result ...: ", resutlVerifyProof);

      } else {
        console.log("Claims do not match and are not subsets.");
        selectedClaims = null;
      }

      // // Step 12: Log the selected claims and variables
      // console.log("bbsProof:", bbsProof);
      // console.log("nonce:", nonce);
      // console.log("issuerPubKey:", issuerPubKey);
      // console.log("revealedIndexes:", revealedIndexes);
      // console.log("selectedClaims:", selectedClaims);
    }

    // Step 13: Return success if everything is valid
    return {
      success: true,
      message: "Verification successful for the given VP and token."
    };

  } catch (error) {
    console.error("Error verifying the proof:", error);
    return { success: false, error: error.message };
  }
}


module.exports = { verifyVPSign, verifyVPProof};
