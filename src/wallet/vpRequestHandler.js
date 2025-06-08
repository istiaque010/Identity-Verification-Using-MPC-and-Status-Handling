const { Wallet } = require('./wallet');  // Correct path to the Wallet class
const jwt = require('jsonwebtoken');  // For decoding the JWT

async function vpRequestHandler(verifierAccessToken, holderDid, holderWallet, verifierDid) {
  try {

    console.log("Access token verification has started...");
    const decodedToken = verifierAccessToken;  // Decode JWT without verifying
    //console.log("Decoded Token:", decodedToken);

    // Step 1: Check if the token has expired
    const currentTime = new Date().toISOString();
    if (decodedToken.payload.expiration < currentTime) {
      throw new Error("Access token has expired.");
    }
    console.log("Access token is not expired.");

    // Step 2: Check if the verifierDid matches the one in the token
    if (decodedToken.payload.verifier !== verifierDid) {
      throw new Error("Verifier DID mismatch. Access token is not valid for this verifier.");
    }
    console.log("Verifier DID matches the token.");

    // Step 3: Check if the holderDid matches the one in the token
    if (decodedToken.payload.holder !== holderDid) {
      throw new Error("Holder DID mismatch. Access token is not valid for this holder.");
    }
    console.log("Holder DID matches the token.");

    // Step 4: Retrieve the holder's wallet
    const wallet = holderWallet;  // Access the holder's wallet

    // Step 5: Log the wallet's access tokens to check its contents
    console.log("All Access Tokens in the wallet for Holder DID:", holderDid);
    console.log(wallet.getAccessTokens()); // Log the tokens in the wallet

    // Step 6: Check if the access token exists in the holder's wallet
    const storedAccessToken = wallet.getAccessTokens().find(token => token.payload.jti === decodedToken.payload.jti);

    if (!storedAccessToken) {
      throw new Error("Access token not found in the holder's wallet.");
    }

    // Step 7: Verify that the access token matches the stored token
    if (JSON.stringify(storedAccessToken) !== JSON.stringify(verifierAccessToken)) {
      console.log("Access tokens do not match.");
      throw new Error("The access token in the wallet does not match the provided token.");
    }

    console.log("Access token is valid and matches the one in the holder's wallet.");

  // Step 7: Retrieve the VP from the holder's wallet where vp_id matches
  const vpId = decodedToken.payload.vp_id;  // Get vp_id from the token payload
  const vp = wallet.getVPs().find(vp => vp.id === vpId);  // Find the VP with the matching id in wallet
  if (!vp) {
    throw new Error(`Verifiable Presentation with ID ${vpId} not found in holder's wallet.`);
  }
  //console.log("Found this VP in the wallet inside request Handler:", vp);


    // If they match, proceed with your logic or return success
    return {
      success: true,
      vp:vp,
      message: "Access token verified and matched successfully."
    };

  } catch (error) {
    console.error("Error requesting VP:", error);
    return { success: false, error: error.message };
  }
}

module.exports = { vpRequestHandler };
