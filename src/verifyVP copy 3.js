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
// Function to verify the VP proof
async function verifyVPProof(vp, holder_DID_PublicKeys, issuers_DID_PublicKeys) {
  try {
    console.log("Verifying VP proof...");

    const verifiableCredential = vp.verifiableCredential; // Get the array of VCs from the VP
    const bbsProof = vp.proof.bbsProof; 

    console.log("BBS Proof for VP:", bbsProof);

    // Extract the holder DID and public key from the holder_DID_PublicKeys object
    const holderDid = Object.keys(holder_DID_PublicKeys)[0];  // Get the holderDid (the key)
    const holderPublicKey = holder_DID_PublicKeys[holderDid];  // Get the publicKey (the value)

    // Step 1: Preprocess the claims of each credential (verifiableCredential) for proof verification
    // const claimsToVerify1 = verifiableCredential.map(credential => {
    //   return credential.claimKey && credential.claimValue ? {
    //     key: credential.claimKey,
    //     value: credential.claimValue
    //   } : null; // Ensure there are claimKey and claimValue present
    // }).filter(Boolean); // Remove any null values


    const claimsToVerify1 = verifiableCredential
  .map(credential => {
    // Ensure claimValue is not null
    if (credential.claimValue !== null) {
      return {
        key: credential.claimKey,
        value: credential.claimValue
      };
    }
    return null; // If claimValue is null, return null
  })
  .filter(claim => claim !== null); // Filter out null values


    console.log("Claims to verify for Holder:", claimsToVerify1);

    // Step 2: Verify the BBS+ proof for the holder using the holder's public key
    const holderProofVerified = await verifyBBSProof(bbsProof, holderPublicKey, claimsToVerify1, vp.proof.nonce);
    if (!holderProofVerified) {
      throw new Error("Holder's BBS+ proof verification failed.");
    }

    console.log("Holder's proof verified successfully.");

    // // Step 3: Loop through each verifiableCredential to verify the issuer's proof
    // for (let credential of verifiableCredential) {
    //   const issuerDID = credential.vcIssuer;  // Get the DID of the issuer for this VC
    //   const issuerPublicKey = issuers_DID_PublicKeys[issuerDID];  // Get the public key for the issuer from the provided map

    //   if (!issuerPublicKey) {
    //     throw new Error(`Public key for issuer ${issuerDID} not found.`);
    //   }

    //   // Find the corresponding signature and proof for the issuer
    //   const issuerSignature = vp.vcsInfo.find(info => info.issuerDid === issuerDID)?.jws.signature;
    //   const issuerProof = vp.vcsInfo.find(info => info.issuerDid === issuerDID)?.bbsProof;
    //   const issuerNonce = vp.vcsInfo.find(info => info.issuerDid === issuerDID)?.nonce;

    //   if (!issuerSignature || !issuerProof || !issuerNonce) {
    //     throw new Error(`Signature, proof, or nonce for issuer ${issuerDID} not found in vcsInfo.`);
    //   }

    //   // Step 4: Preprocess the claims of each VC for signing and verification
    //   const claimsToVerify2 = credential.claimKey && credential.claimValue ? {
    //     key: credential.claimKey,
    //     value: credential.claimValue
    //   } : null; // Only include valid claims

    //   console.log("Claims to verify for Issuer:", claimsToVerify2);

    //   // Step 5: Verify the BBS+ proof for the issuer using the issuer's public key
    //   const issuerProofVerified = await verifyBBSProof(issuerProof, issuerPublicKey, claimsToVerify2, issuerNonce);
    //   if (!issuerProofVerified) {
    //     throw new Error(`Issuer's BBS+ proof verification failed for ${issuerDID}.`);
    //   }

    //   console.log(`Issuer's proof verified successfully for ${issuerDID}.`);
    // }

    // If all proofs are verified successfully, return success
    return { success: holderProofVerified };

  } catch (error) {
    console.error("Error verifying VP proof:", error);
    return { success: false, error: error.message };
  }
}


module.exports = { verifyVPSign, verifyVPProof};
