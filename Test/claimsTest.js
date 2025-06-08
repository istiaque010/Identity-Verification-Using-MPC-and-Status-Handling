const fs = require('fs');
const { keccak256 } = require('js-sha3');

// Number of iterations to average timing and memory measurements
const NUM_ITERATIONS = 5;

// Load JSON file and get claims for specified credential type
function loadClaims(filePath, credentialType) {
  const data = fs.readFileSync(filePath, 'utf8');
  const json = JSON.parse(data);
  if (!json[credentialType]) {
    throw new Error(`Credential type "${credentialType}" not found in JSON.`);
  }
  return json[credentialType];
}

// Generate 16-byte cryptographically secure salt
function generateSalt() {
  return Buffer.from(cryptoRandomBytes(16));
}

// Helper for secure random bytes (Node.js crypto)
function cryptoRandomBytes(length) {
  return require('crypto').randomBytes(length);
}

// Hash claim value with salt using keccak256 (like Solidity)
function hashClaimWithSalt(claimValue, salt) {
  const valueBuffer = Buffer.from(claimValue, 'utf8');
  const combined = Buffer.concat([valueBuffer, salt]);
  const hashHex = keccak256(combined);
  return hashHex;
}

// Get current heap used memory in bytes with manual GC
function getMemoryUsageBytes() {
  if (global.gc) {
    global.gc();
  } else {
    console.warn('No GC hook! Run node with --expose-gc flag.');
  }
  return process.memoryUsage().heapUsed;
}

// Compute root hash from all claim hashes + root salt using keccak256
function computeRootHash(hashes, rootSalt) {
  if (!Buffer.isBuffer(rootSalt)) {
    rootSalt = Buffer.from(rootSalt, 'hex');
  }
  const hashBuffers = hashes.map(h => Buffer.from(h, 'hex'));
  const combined = Buffer.concat([rootSalt, ...hashBuffers]);
  return keccak256(combined);
}

// Process claims with timing and memory measurement and compute root hash
function processClaimsWithMetrics(claims) {
  // Clear and measure initial memory
  const initialMemory = getMemoryUsageBytes();

  let totalTimeNs = 0n;
  const results = [];

  for (const { key, value } of claims) {
    const start = process.hrtime.bigint();

    const salt = generateSalt();
    const hash = hashClaimWithSalt(value, salt);

    const end = process.hrtime.bigint();
    const durationNs = end - start;
    totalTimeNs += durationNs;

    results.push({
      key,
      value,
      salt: salt.toString('hex'),
      hash,
      hashingTimeNs: durationNs.toString(),
    });
  }

  // Clear and measure final memory
  const finalMemory = getMemoryUsageBytes();
  const memoryUsedBytes = finalMemory - initialMemory;
  const avgMemoryPerClaim = memoryUsedBytes / claims.length;

  const avgTimeNs = totalTimeNs / BigInt(claims.length);
  const avgTimeMs = Number(avgTimeNs) / 1e6;

  // Measure root hash computation time
  const rootSalt = generateSalt();
  const allHashes = results.map(r => r.hash);

  const rootStart = process.hrtime.bigint();
  const rootHash = computeRootHash(allHashes, rootSalt);
  const rootEnd = process.hrtime.bigint();
  const rootHashDurationNs = rootEnd - rootStart;
  const rootHashDurationMs = Number(rootHashDurationNs) / 1e6;

  return {
    results,
    averageHashingTimeMs: avgTimeMs,
    averageMemoryUsageBytes: avgMemoryPerClaim,
    rootSalt: rootSalt.toString('hex'),
    rootHash,
    rootHashingTimeMs: rootHashDurationMs,
  };
}

// Run multiple iterations to average results
function runMultipleIterations(claims, iterations) {
  let sumHashTime = 0;
  let sumMemoryUsage = 0;
  let sumRootHashTime = 0;
  let lastResults = null;

  for (let i = 0; i < iterations; i++) {
    const {
      results,
      averageHashingTimeMs,
      averageMemoryUsageBytes,
      rootSalt,
      rootHash,
      rootHashingTimeMs,
    } = processClaimsWithMetrics(claims);

    sumHashTime += averageHashingTimeMs;
    sumMemoryUsage += averageMemoryUsageBytes;
    sumRootHashTime += rootHashingTimeMs;
    lastResults = { results, rootSalt, rootHash }; // Keep last for detailed output
  }

  return {
    averageHashingTimeMs: sumHashTime / iterations,
    averageMemoryUsageBytes: sumMemoryUsage / iterations,
    averageRootHashingTimeMs: sumRootHashTime / iterations,
    results: lastResults.results,
    rootSalt: lastResults.rootSalt,
    rootHash: lastResults.rootHash,
  };
}

// Main function
function main() {
  const filePath = './updated_claims.json'; // file path in same folder
  const credentialType = 'Driving_License';

  try {
    const claims = loadClaims(filePath, credentialType);

    const {
      averageHashingTimeMs,
      averageMemoryUsageBytes,
      averageRootHashingTimeMs,
      results,
      rootSalt,
      rootHash,
    } = runMultipleIterations(claims, NUM_ITERATIONS);

    console.log("Processed Claims (from last iteration):");
    console.log(JSON.stringify(results, null, 2));
    console.log(`\nAverage hashing time per claim (averaged over ${NUM_ITERATIONS} runs): ${averageHashingTimeMs.toFixed(4)} ms`);
    console.log(`Average memory usage per claim (averaged over ${NUM_ITERATIONS} runs): ${averageMemoryUsageBytes.toFixed(2)} bytes`);
    console.log(`Average root hashing time (averaged over ${NUM_ITERATIONS} runs): ${averageRootHashingTimeMs.toFixed(4)} ms`);
    console.log(`Root Salt (last run): ${rootSalt}`);
    console.log(`Root Hash (last run): ${rootHash}`);

  } catch (error) {
    console.error(error.message);
  }
}

main();
