const fs = require('fs');
const crypto = require('crypto');

// Compute root hash: SHA-256 of (rootSalt + all claim hashes)
function computeRootHash(hashes, rootSalt) {
  const saltBuffer = Buffer.from(rootSalt, 'hex');
  const hashBuffers = hashes.map(h => Buffer.from(h, 'hex'));
  const combined = Buffer.concat([saltBuffer, ...hashBuffers]);
  return crypto.createHash('sha256').update(combined).digest('hex');
}

// Load claim hashes from JSON file
function loadClaimHashes(filePath) {
  const raw = fs.readFileSync(filePath, 'utf8');
  const json = JSON.parse(raw);
  return json.hashes;
}

// Brute-force root salt to match the root hash
function bruteForceRootHash(claimHashes, targetRootHash, numTries = 1000000) {
  const startTime = process.hrtime.bigint();

  for (let i = 0; i < numTries; i++) {
    const rootSalt = crypto.randomBytes(16); // Try a new 16-byte salt
    const rootHash = computeRootHash(claimHashes, rootSalt.toString('hex'));

    if (rootHash === targetRootHash) {
      const endTime = process.hrtime.bigint();
      const durationMs = Number(endTime - startTime) / 1e6;

      return {
        success: true,
        matchingRootSalt: rootSalt.toString('hex'),
        rootHash,
        tries: i + 1,
        timeMs: durationMs.toFixed(3)
      };
    }

    if ((i + 1) % 100000 === 0) {
      console.log(`Tried ${i + 1} root salts...`);
    }
  }

  const endTime = process.hrtime.bigint();
  const durationMs = Number(endTime - startTime) / 1e6;

  return {
    success: false,
    message: 'No matching salted root  found.',
    tries: numTries,
    timeMs: durationMs.toFixed(3)
  };
}

// === CONFIGURE HERE VC===
//const hashFile = './claim_hashesVC.json'; // JSON file with "hashes": [ ... ]
//const targetRootHash = 'd0e315da277c30ae26695894e543fad4fa2fe2ecab7f0a3139b0bb873e978845'; // 
//const maxTries = 1000000; // 10^6

//for Driving lichecnce
//root VC d0e315da277c30ae26695894e543fad4fa2fe2ecab7f0a3139b0bb873e978845



  // === CONFIGURE HERE VC===
const hashFile = './claim_hashesVP.json'; // JSON file with "hashes": [ ... ]
const targetRootHash = 'f7b638f60dbf931f4b1935a4f9e6b5069a1078f88a2f5a49b9b931d8c0c5e8af'; // 
const maxTries = 1000000; // 10^6
  
 //for Driving lichecnce salt: 0123456789abcdef0123456789abcdef
  //root VP f7b638f60dbf931f4b1935a4f9e6b5069a1078f88a2f5a49b9b931d8c0c5e8af

// === RUN ===
try {
  const claimHashes = loadClaimHashes(hashFile);
  const result = bruteForceRootHash(claimHashes, targetRootHash, maxTries);
  console.log(result);
} catch (err) {
  console.error('Error:', err.message);
}
