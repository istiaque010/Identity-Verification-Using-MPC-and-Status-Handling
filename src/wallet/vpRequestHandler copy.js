const Wallet = require('./wallet');  // Import the Wallet class
const jwt = require('jsonwebtoken');  // For decoding the JWT

async function vpRequestHandler(verifierAccessToken, holderDid, holderWallet, verifierDid) {
  try {
    const decodedToken = verifierAccessToken;  // Decode JWT without verifying
    
    console.log("Decoded Token:", decodedToken);

    // Step 1: Check if the token has expired
    const currentTime = new Date().toISOString();
    if (decodedToken.payload.expiration < currentTime) {
      throw new Error("Access token has expired.");
    }

    // Step 2: Verify that the access token is for the correct verifier DID
    if (decodedToken.payload.verifier !== verifierDid) {
      console.log("Verifier DID mismatch:", decodedToken.payload.verifier);
      console.log("Verifier DID mismatch:", verifierDid);
      throw new Error("The access token is not valid for this verifier.");
    }

    // Step 3: Verify that the token belongs to the correct holder DID
    if (decodedToken.payload.holder !== holderDid) {
      throw new Error("The access token is not valid for this holder.");
    }

    // Step 4: Retrieve the holder's wallet
    const wallet = holderWallet;  // Instantiate the Wallet class

    // Step 5: Log the wallet's access tokens to check its contents
    console.log("All Access Tokens in the wallet for Holder DID:", holderDid);
    console.log(wallet.getAccessTokens()); // Log the tokens in the wallet

    // Step 6: Check if the access token exists in the holder's wallet
    const storedAccessToken = wallet.getAccessTokens().find(token => token.payload.jti === decodedToken.payload.jti);
    if (!storedAccessToken) {
      throw new Error("Access token not found in the holder's wallet.");
    }

    // Step 7: Parse claims
    const claims = JSON.parse(decodedToken.payload.claims);  // Claims are in string format, need to parse it
    console.log("Parsed Claims:", claims);

    // Step 8: Retrieve the VP using the vpId from the wallet
    const vp = wallet.getVPs().find(vp => vp.id === decodedToken.payload.vp_id);
    if (!vp) {
      throw new Error(`Verifiable Presentation with ID ${decodedToken.payload.vp_id} not found in wallet.`);
    }

    console.log("Found this VP in the wallet inside request Handler:", vp);

    // Step 9: Validate and extract the selected claims from the VP
    //const allClaims = vp.verifiableCredential.map(vc => vc.credentialSubject.claims).flat();

    const allClaims= vp.verifiableCredential;  // because we do not need maping this time
    const selectedClaims = decodedToken.payload.selectedIndexes.map(index => allClaims[index]).filter(Boolean);

    //

    if (selectedClaims.length === 0) {
      throw new Error("No valid claims selected.");
    }

    // Return the valid claims and the VP object
    return {
      success: true,
      vp: vp, // The full VP to provide to the verifier
      claims: selectedClaims, // The valid selected claims
    };

  } catch (error) {
    console.error("Error requesting VP:", error);
    return { success: false, error: error.message };
  }
}

module.exports = { vpRequestHandler };
