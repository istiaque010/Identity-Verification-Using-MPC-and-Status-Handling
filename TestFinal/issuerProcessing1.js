const fs = require('fs');
const crypto = require('crypto');

// Number of iterations to average timing and memory measurements
const NUM_ITERATIONS = 5;

// Example issuer, holder, and verifier DIDs
const issuerDID = 'did:ethr:0x742d35Cc6634C0532925a3b844Bc454e4438f44e';
const holderDID = 'did:ethr:0x267be1c1d684f78cb4f6a176c4911b741e4ffdc0';
const verifierDID = 'did:ethr:0x3f5CE5FBFe3E9af3971dD833D26BA9b5C936f0bE';

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

// Compute VP root from multiple VC roots + VP salt
function computeVPRoot(vcRoots, vpSalt) {
  const rootBuffers = vcRoots.map(root => Buffer.from(root, 'hex'));
  const saltBuffer = Buffer.isBuffer(vpSalt) ? vpSalt : Buffer.from(vpSalt, 'hex');
  const combined = Buffer.concat([...rootBuffers, saltBuffer]);
  return crypto.createHash('sha256').update(combined).digest('hex');
}

// Process claims with timing and memory measurement per claim for better granularity
function processClaimsWithMetrics(claims) {
  let totalTimeNs = 0n;
  let totalMemoryDiff = 0;
  const results = [];

  for (const { key, value } of claims) {
    const memBefore = getMemoryUsageBytes();
    const start = process.hrtime.bigint();
    const hash = hashClaim(value);
    const end = process.hrtime.bigint();
    const memAfter = getMemoryUsageBytes();

    results.push({
      key,
      value,
      hash,
      hashingTimeNs: (end - start).toString(),
    });

    totalTimeNs += (end - start);
    totalMemoryDiff += (memAfter - memBefore);
  }

  const avgMemoryPerClaim = totalMemoryDiff / claims.length;
  const avgTimeMs = Number(totalTimeNs / BigInt(claims.length)) / 1e6;

  const rootSalt = crypto.randomBytes(32);
  const preRoot = computePreRoot(results.map(r => r.hash));
  const rootStart = process.hrtime.bigint();
  const rootHash = computeRootHash(preRoot, rootSalt);
  const rootEnd = process.hrtime.bigint();
  const rootHashTimeMs = Number(rootEnd - rootStart) / 1e6;
  const vcId = sha256Concat(issuerDID, holderDID, rootSalt);

  const avgClaimSizeBytes = claims.reduce((sum, c) => sum + Buffer.byteLength(c.value, 'utf8'), 0) / claims.length;

  return {
    results,
    averageHashingTimeMs: avgTimeMs,
    averageMemoryUsageBytes: avgMemoryPerClaim,
    averageClaimSizeBytes: avgClaimSizeBytes,
    rootSalt: rootSalt.toString('hex'),
    preRoot,
    lastRootHash: rootHash,
    rootHashTimeMs,
    vcId,
  };
}

// Run multiple iterations to average results
function runMultipleIterations(claims, iterations) {
  let sumHashTime = 0;
  let sumMemoryUsage = 0;
  let sumRootHashTime = 0;
  let sumClaimSize = 0;
  let lastResults = null;

  for (let i = 0; i < iterations; i++) {
    const result = processClaimsWithMetrics(claims);
    sumHashTime += result.averageHashingTimeMs;
    sumMemoryUsage += result.averageMemoryUsageBytes;
    sumRootHashTime += result.rootHashTimeMs;
    sumClaimSize += result.averageClaimSizeBytes;
    lastResults = result;
  }

  return {
    averageHashingTimeMs: sumHashTime / iterations,
    averageMemoryUsageBytes: sumMemoryUsage / iterations,
    averageRootHashingTimeMs: sumRootHashTime / iterations,
    averageClaimSizeBytes: sumClaimSize / iterations,
    ...lastResults,
  };
}

// Main function
function main() {
  const filePath = './updated_claims.json';

  const credentialTypes = ['Residence_Card', 'Passport', 'Driving_License'];
  const allVCRoots = [];
  const allOutputs = {};

  for (const credentialType of credentialTypes) {
    try {
      const claims = loadClaims(filePath, credentialType);
      const result = runMultipleIterations(claims, NUM_ITERATIONS);

      allVCRoots.push(result.lastRootHash);

      const output = {
        credentialType,
        issuerDID,
        holderDID,
        verifierDID,
        processedClaims: result.results,
        averageHashingTimeMs: result.averageHashingTimeMs.toFixed(4),
        averageMemoryUsageBytes: result.averageMemoryUsageBytes.toFixed(2),
        averageClaimSizeBytes: result.averageClaimSizeBytes.toFixed(2),
        averageRootHashingTimeMs: result.averageRootHashingTimeMs.toFixed(4),
        rootSalt: result.rootSalt,
        preRoot: result.preRoot,
        rootHash: result.lastRootHash,
        vcId: result.vcId,
      };

      allOutputs[credentialType] = output;

      console.log(`\n--- Results for credential type: ${credentialType} ---`);
      console.log("Processed Claims (from last iteration):");
      console.log(JSON.stringify(output.processedClaims, null, 2));
      console.log(`Average claim size per claim (averaged over ${NUM_ITERATIONS} runs): ${output.averageClaimSizeBytes} bytes`);
      console.log(`Average hashing time per claim (averaged over ${NUM_ITERATIONS} runs): ${output.averageHashingTimeMs} ms`);
      console.log(`Average memory usage per claim (averaged over ${NUM_ITERATIONS} runs): ${output.averageMemoryUsageBytes} bytes`);
      console.log(`Average root hashing time (averaged over ${NUM_ITERATIONS} runs): ${output.averageRootHashingTimeMs} ms`);
      console.log(`Root Salt (last iteration): ${output.rootSalt}`);
      console.log(`Pre Root (last iteration): ${output.preRoot}`);
      console.log(`Root Hash (last iteration): ${output.rootHash}`);
      console.log(`VC ID (last iteration): ${output.vcId}`);

      // Save individual file with DIDs included
      const outputFileName = `${credentialType.replace(/\s+/g, '_')}.json`;
      fs.writeFileSync(outputFileName, JSON.stringify(output, null, 2), 'utf8');
      console.log(`✅ Output successfully written to ${outputFileName}`);

    } catch (error) {
      console.error(`❌ Error processing credential type "${credentialType}":`, error.message);
    }
  }

  // Compute VP root for all VCs
  const vpSalt = crypto.randomBytes(32);
  const vpRoot = computeVPRoot(allVCRoots, vpSalt);

  console.log('\n=== Verifiable Presentation (VP) Root Computation ===');
  console.log('VP Salt (hex):', vpSalt.toString('hex'));
  console.log('VP Root:', vpRoot);

  const vpOutput = {
    vpSalt: vpSalt.toString('hex'),
    vpRoot,
    vcRoots: allVCRoots,
    issuerDID,
    holderDID,
    verifierDID,
  };

  allOutputs['VP_Root'] = vpOutput;

  // Save VP output to file with DIDs included
  fs.writeFileSync('vp_root.json', JSON.stringify(vpOutput, null, 2), 'utf8');
  console.log('✅ VP root info saved to vp_root.json');

  // Save combined output file with DIDs included
  fs.writeFileSync('output.json', JSON.stringify(allOutputs, null, 2), 'utf8');
  console.log('✅ All outputs saved to output.json');

  // Print all DIDs at the end for clarity
  console.log('\n--- DID Information Summary ---');
  console.log('Issuer DID:', issuerDID);
  console.log('Holder DID:', holderDID);
  console.log('Verifier DID:', verifierDID);
}

main();
