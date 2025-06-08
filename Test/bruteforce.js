const crypto = require('crypto');

// Function to hash value with salt using SHA-256
function hashWithSalt(value, salt) {
  const combined = Buffer.concat([salt, Buffer.from(value, 'utf8')]);
  return crypto.createHash('sha256').update(combined).digest('hex');
}

// Brute-force over N random salts to match the hash
function bruteForceSalt(value, targetHash, numTries = 1000000) {
  const startTime = process.hrtime.bigint(); // Start high-res timer

  for (let i = 0; i < numTries; i++) {
    const salt = crypto.randomBytes(16);
    const hash = hashWithSalt(value, salt);

    if (hash === targetHash) {
      const endTime = process.hrtime.bigint();
      const durationMs = Number(endTime - startTime) / 1e6;

      return {
        success: true,
        matchingSalt: salt.toString('hex'),
        hash,
        tries: i + 1,
        timeMs: durationMs.toFixed(3)
      };
    }

    if ((i + 1) % 100000 === 0) {
      console.log(`Tried ${i + 1} salts...`);
    }
  }

  const endTime = process.hrtime.bigint();
  const durationMs = Number(endTime - startTime) / 1e6;

  return {
    success: false,
    message: 'No matching salt found in 1 million tries.',
    totalTries: numTries,
    timeMs: durationMs.toFixed(3)
  };
}


// Example input
const value = "2020-05-15";
const targetHash = "d80f614410635fbee67ea33a26eb23d52f7b2883ad48e0e3db1250b1a62b4659"; // Replace this with actual known hash

// Run brute-force and track time
const result = bruteForceSalt(value, targetHash, 1000000);
console.log(result);





