const fs = require('fs');
// In main.js
const { generateBBSKeyPair } = require('./src/crypto/bbsPlus');  // Import BBS+ key generation function
const { createVC } = require('./src/issuer/vcGenerator');  // Import VC generator function
const Wallet = require('./src/wallet/wallet');  // Import Wallet class
const { selectClaims } = require('./src//wallet/selectClaims');  // Import selectClaims function
const { createVP } = require('./src/wallet/vpGenerator'); // Import to generate the vp
const { generateAccessToken } = require('./src/wallet/accessTokenGenerator');  // Adjust the path as needed
const { vpRequestHandler } = require('./src/wallet/vpRequestHandler');  // Adjust the path as needed
const { verifyVPSign, verifyVPProof } = require('./src/verifyVP');  // Import verifyVP function


async function testMain() {
  try {
  

    // Read DIDs and claims
    const dids = JSON.parse(fs.readFileSync('./dids.json', 'utf8'));  // Read DIDs
    const claimsData = JSON.parse(fs.readFileSync('./claims.json', 'utf8'));  // Read Claims

    // Get the holder
    const holderDid = dids.holders.holder1;

     // Create wallet for the holder
     const holderWallet = new Wallet(holderDid);


    //-----------------------------------------------VCs----------------------------------------
    //------------NID---------------------------------------
    // Get the  nidIssuer DIDs
    const nidIssuerDID = dids.issuers.nidIssuer;

    // Generate the BBS+ key pair for the NID issuer
    const result1 = await generateBBSKeyPair();
    const keyPair1 = result1.keyPair;

    const { keyPair } = await generateBBSKeyPair();
    console.log(`Generated BBS+ Key Pair for issuerNID ${nidIssuerDID}`);
    console.log("Public Key issuerNID:", keyPair1.publicKey);
    console.log("Private Key issuerNID:",keyPair1.secretKey);

    // Create VC for the holder with NID claims
    const vc1 = await createVC(holderDid, nidIssuerDID, claimsData.NID, keyPair1);
    console.log("Generated NID VC:", JSON.stringify(vc1, null, 2));
    // Add VC to the wallet
    holderWallet.addVC(vc1);

    //------------Passport---------------------------------------
    // Get the  and passportIssuer DIDs
    const passportIssuerDID = dids.issuers.passportIssuer;

    
     // Generate the BBS+ key pair for the passport issuer
     const result2 = await generateBBSKeyPair();
     const keyPair2 = result2.keyPair;


    console.log(`Generated BBS+ Key Pair for passportIssuerDID ${passportIssuerDID}`);
    console.log("Public Key passportIssuerDID:", keyPair2.publicKey);
    console.log("Private Key passportIssuerDID:", keyPair2.secretKey);

    // Create VC for the holder with passport claims
    const vc2 = await createVC(holderDid, passportIssuerDID, claimsData.Passport, keyPair2);
    console.log("Generated passport VC:", JSON.stringify(vc2, null, 2));
    // Add VC to the wallet
    holderWallet.addVC(vc2);

     //------------Driving Licence---------------------------------------
    // Get the  and passportIssuer DIDs
    const drivingLicenseIssuerDID = dids.issuers.drivingLicenseIssuer;

   
     // Generate the BBS+ key pair for the Driving Lichence issuer
     const result3 = await generateBBSKeyPair();
     const keyPair3 = result3.keyPair;


    console.log(`Generated BBS+ Key Pair for drivingLicenseIssuerDID ${drivingLicenseIssuerDID}`);
    console.log("Public Key drivingLicenseIssuerDID:", keyPair3.publicKey);
    console.log("Private Key drivingLicenseIssuerDID:", keyPair3.secretKey);

    // Create VC for the holder with NID claims
    const vc3 = await createVC(holderDid, drivingLicenseIssuerDID, claimsData.Driving_License, keyPair3);
    console.log("Generated driving License VC:", JSON.stringify(vc3, null, 2));
    // Add VC to the wallet
    holderWallet.addVC(vc3);

    //console.log("Driving License Claims:", JSON.stringify(claimsData.Driving_License, null, 2)); // Log only Driving License claims

    //------------Print all VCs---------------------------------------
    // Print all VCs in the wallet for the holder
    console.log("All VCs from the wallet for Holder DID:", holderDid);
    console.log(JSON.stringify(holderWallet.getVCs(), null, 2));

     //-----------------------------------------------End VCs----------------------------------------

    //-----------------VP---------------------------------------------------------------
     
    
     // Generate the BBS+ key pair for the vp Holder
     const result4 = await generateBBSKeyPair();
     const keyPair4 = result4.keyPair;

    //----------------vp-1---------------------------------------------------
    // Now, use selectClaims to select claims from the wallet
    
    const selectedClaimsResult1 = await selectClaims(holderDid, holderWallet);
    //const selectedClaims1 =  selectedClaimsResult1.selectedClaims;
    const vcsInfo1= selectedClaimsResult1.vcsInfo;
     console.log("Inside main vcsInfo1:", vcsInfo1);



     // test it later firs confirms selected claims

    // Generate vp for the Holder
    // const vp1 = await createVP(holderDid, selectedClaims1, vcsInfo1, keyPair4);
    // console.log("Generated Verifiable Presentation (VP):", JSON.stringify(vp1, null, 2));
    // holderWallet.addVP(vp1); // Add the VP to the wallet

    //----------------vp-2---------------------------------------------------
    // Now, use selectClaims to select claims from the wallet
    //const selectedClaimsResult2 = await selectClaims(holderDid, holderWallet);
    //const selectedClaims2 =  selectedClaimsResult2.selectedClaims;
    //const vcsInfo2= selectedClaimsResult2.vcsInfo;
     //console.log("Final selected claims:", selectedClaims2);
    
    // Generate vp for the Holder
    //const vp2 = await createVP(holderDid, selectedClaims2,vcsInfo2, keyPair4);
    //console.log("Generated Verifiable Presentation (VP):", JSON.stringify(vp2, null, 2));
    //holderWallet.addVP(vp2); // Add the VP to the wallet


    //------------Print all VPs---------------------------------------
    // Print all VCs in the wallet for the holder
    console.log("All VPs from the wallet for Holder DID :", holderDid);
    console.log(JSON.stringify(holderWallet.getVPs(), null, 2));


     //-------------------End vp----------------------------------------------------------



    //-------------------Request Access VP ----------------------------------------------------------


    const verifierDid = dids.verifiers.verifier1; // Define a verifier DID
    console.log("Verifier DID :", verifierDid);
    const vpId = vp1.id; // Use the vpId from the generated VP
    console.log("Verifiable Presentaion ID :", vpId);
   
    const accessToken1 = await generateAccessToken(holderDid, verifierDid, vpId, holderWallet, keyPair4);
    console.log("Generated Access Token:", accessToken1);

    // Add access token to wallet
    holderWallet.addAccessToken(accessToken1);
    console.log("All Access Tokens in the wallet for Holder DID:", holderDid);
    console.log(JSON.stringify(holderWallet.getAccessTokens(), null, 2));


    //Add same access token to the verifir wallet 
     // Create wallet for the holder
     const verifierWallet = new Wallet(verifierDid);
    // Add access token to verifier  wallet
    verifierWallet.addAccessToken(accessToken1);

    console.log("All Access Tokens in the wallet for Verifier DID:", verifierDid);
    console.log(JSON.stringify(verifierWallet.getAccessTokens(), null, 2));



    //-------------------End Request Access VP----------------------------------------------------------


    //-------------------Handle vp Access request----------------------------------------------------------

     //const holderDid = "did:example:holder123";  // The holder DID (provided in the token)
    //const verifierDid = "did:example:university123";  // The verifier DID (provided in the token)
   
    const accessTokens = verifierWallet.getAccessTokens();
    const verifierAccessToken = accessTokens[0];;  // The access token provided by the verifier
  
    // Request the VP from the holder using the access token
    const result = await vpRequestHandler(verifierAccessToken, holderDid,holderWallet, verifierDid); // for testing we pass holder walelt but it will come actually from DB
    
    if (result.success) {
      console.log("Verified Access Token successfully!");
      console.log("Sending the Verifiable Presentation to the verifier...");
      console.log("Verified Claims:", result.claims);
      console.log("Sending VP:", JSON.stringify(result.vp, null, 2));  // Send the VP to the verifier
    } else {
      console.log("Access Token verification failed:", result.error);
    }


      //-------------------End Handle vp Access request----------------------------------------------------------


    //-------------------This is verifying signature and will work only when all the claims are part pf vp, Verify VP ----------------------------------------------------------------------------
    //I tested it only for holder, this logic is not for issuser
    const holder_DID_PublicKeys = {
        [holderDid]: keyPair4.publicKey 
      };
    
    const issuers_DID_PublicKeys = {
        [nidIssuerDID]: keyPair1.publicKey,
        [passportIssuerDID]: keyPair2.publicKey,
        [drivingLicenseIssuerDID]: keyPair3.publicKey
      };


      console.log("issuers_DID_PublicKeys ", issuers_DID_PublicKeys);

    // verify vp , here vp= result.vp which is gotten from previous step
    // const verificationResult = await verifyVPSign(result.vp, holder_DID_PublicKeys, issuers_DID_PublicKeys);
    // console.log("vp Signature verification result ", verificationResult);
     

    //-------------------End Verify VP Signature ----------------------------------------------------------------------------


    //------------------- Verify VP Proof ----------------------------------------------------------------------------

       // verify vp , here vp= result.vp which is gotten from previous step
    const proofVerificationResult = await verifyVPProof(result.vp, holder_DID_PublicKeys, issuers_DID_PublicKeys);
    console.log("vp Proof proofVerificationResult result:", proofVerificationResult);

    //-------------------End Verify VP Proof ----------------------------------------------------------------------------


  } catch (error) {
    console.error("Error in VC generation:", error);
  }
}

// Run the VC generation test
testMain();
