const fs = require('fs');
const crypto = require('crypto');

// Number of iterations to average timing and memory measurements
const NUM_ITERATIONS = 5;

// Example issuer and holder DIDs
const issuerDID = 'did:example:issuer123';
const holderDID = 'did:example:holder456';

// Load JSON file and get claims for specified credential type
function loadClaims(filePath, credentialType) {
  const data = fs.readFileSync(filePath, 'utf8');
  const json = JSON.parse(data);
  if (!json[credentialType]) {
    throw new Error(`Credential type "${credentialType}" not found in JSON.`);
  }
  return json[credentialType];
}

// Hash claim value using SHA-256
function hashClaim(claimValue) {
  return crypto.createHash('sha256').update(Buffer.from(claimValue, 'utf8')).digest('hex');
}

// Compute SHA-256 hash of concatenated inputs
function sha256Concat(...inputs) {
  const buffers = inputs.map(input =>
    typeof input === 'string' ? Buffer.from(input, 'utf8') : input
  );
  const combined = Buffer.concat(buffers);
  return crypto.createHash('sha256').update(combined).digest('hex');
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

// Compute combined root hash (pre_root)
function computePreRoot(hashes) {
  const hashBuffers = hashes.map(h => Buffer.from(h, 'hex'));
  const combined = Buffer.concat(hashBuffers);
  return crypto.createHash('sha256').update(combined).digest('hex');
}

// Compute root hash from preRoot and salt
function computeRootHash(preRoot, rootSalt) {
  if (!Buffer.isBuffer(rootSalt)) {
    rootSalt = Buffer.from(rootSalt, 'hex');
  }
  const combined = Buffer.concat([Buffer.from(preRoot, 'hex'), rootSalt]);
  return crypto.createHash('sha256').update(combined).digest('hex');
}

// Process claims with timing and memory measurement
function processClaimsWithMetrics(claims) {
  const initialMemory = getMemoryUsageBytes();

  let totalTimeNs = 0n;
  const results = [];

  for (const { key, value } of claims) {
    const start = process.hrtime.bigint();
    const hash = hashClaim(value);
    const end = process.hrtime.bigint();

    results.push({
      key,
      value,
      hash,
      hashingTimeNs: (end - start).toString(),
    });

    totalTimeNs += end - start;
  }

  const finalMemory = getMemoryUsageBytes();
  const avgMemoryPerClaim = (finalMemory - initialMemory) / claims.length;
  const avgTimeMs = Number(totalTimeNs / BigInt(claims.length)) / 1e6;

  const rootSalt = crypto.randomBytes(32);
  const preRoot = computePreRoot(results.map(r => r.hash));
  const rootStart = process.hrtime.bigint();
  const rootHash = computeRootHash(preRoot, rootSalt);
  const rootEnd = process.hrtime.bigint();
  const rootHashTimeMs = Number(rootEnd - rootStart) / 1e6;
  const vcId = sha256Concat(issuerDID, holderDID, rootSalt);

  return {
    results,
    averageHashingTimeMs: avgTimeMs,
    averageMemoryUsageBytes: avgMemoryPerClaim,
    rootSalt: rootSalt.toString('hex'),
    preRoot,
    rootHash,
    rootHashingTimeMs: rootHashTimeMs,
    vcId,
  };
}

// Run multiple iterations to average results
function runMultipleIterations(claims, iterations) {
  let sumHashTime = 0;
  let sumMemoryUsage = 0;
  let sumRootHashTime = 0;
  let lastResults = null;

  for (let i = 0; i < iterations; i++) {
    const result = processClaimsWithMetrics(claims);
    sumHashTime += result.averageHashingTimeMs;
    sumMemoryUsage += result.averageMemoryUsageBytes;
    sumRootHashTime += result.rootHashingTimeMs;
    lastResults = result;
  }

  return {
    averageHashingTimeMs: sumHashTime / iterations,
    averageMemoryUsageBytes: sumMemoryUsage / iterations,
    averageRootHashingTimeMs: sumRootHashTime / iterations,
    ...lastResults,
  };
}

// Main function
function main() {
  const filePath = './updated_claims.json';
  const credentialType = 'Driving_License';

  try {
    const claims = loadClaims(filePath, credentialType);
    const result = runMultipleIterations(claims, NUM_ITERATIONS);

    const output = {
      processedClaims: result.results,
      averageHashingTimeMs: result.averageHashingTimeMs.toFixed(4),
      averageMemoryUsageBytes: result.averageMemoryUsageBytes.toFixed(2),
      averageRootHashingTimeMs: result.averageRootHashingTimeMs.toFixed(4),
      rootSalt: result.rootSalt,
      preRoot: result.preRoot,
      rootHash: result.rootHash,
      vcId: result.vcId,
    };

    // Print to console (as before)
    console.log("Processed Claims (from last iteration):");
    console.log(JSON.stringify(output.processedClaims, null, 2));
    console.log(`\nAverage hashing time per claim (averaged over ${NUM_ITERATIONS} runs): ${output.averageHashingTimeMs} ms`);
    console.log(`Average memory usage per claim (averaged over ${NUM_ITERATIONS} runs): ${output.averageMemoryUsageBytes} bytes`);
    console.log(`Average root hashing time (averaged over ${NUM_ITERATIONS} runs): ${output.averageRootHashingTimeMs} ms`);
    console.log(`Root Salt (last run): ${output.rootSalt}`);
    console.log(`Pre Root (last run): ${output.preRoot}`);
    console.log(`Root Hash (last run): ${output.rootHash}`);
    console.log(`VC ID (last run): ${output.vcId}`);

    // Save to file
    const outputFileName = `${credentialType}.json`;
    fs.writeFileSync(outputFileName, JSON.stringify(output, null, 2), 'utf8');
    console.log(`\n✅ Output successfully written to ${outputFileName}`);

  } catch (error) {
    console.error("❌ Error:", error.message);
  }
}

main();
