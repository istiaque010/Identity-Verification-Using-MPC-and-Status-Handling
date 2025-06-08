class Wallet {
    constructor(holderDid) {
      this.holderDid = holderDid;  // The DID of the holder
      this.vcs = [];                // List of VCs stored in the wallet
      this.vps = [];                // List of VPs stored in the wallet
      this.accessTokens = [];       // List of access tokens stored in the wallet
    }
  
    // Method to add a VC to the wallet
    addVC(vc) {
      this.vcs.push(vc);
      console.log(`VC added to wallet for ${this.holderDid}:`, JSON.stringify(vc, null, 2));
    }
  
    // Method to add a VP to the wallet
    addVP(vp) {
      this.vps.push(vp);
      console.log(`VP added to wallet for ${this.holderDid}:`, JSON.stringify(vp, null, 2));
    }
  
    // Method to add an access token to the wallet
    addAccessToken(token) {
      this.accessTokens.push(token);
      console.log(`Access token added to wallet for ${this.holderDid}:`, JSON.stringify(token, null, 2));
    }
  
    // Method to get all VCs in the wallet
    getVCs() {
      return this.vcs;
    }
  
    // Method to get all VPs in the wallet
    getVPs() {
      return this.vps;
    }
  
    // Method to get all access tokens in the wallet
    getAccessTokens() {
      return this.accessTokens;
    }
  }
  
  module.exports = Wallet;
  