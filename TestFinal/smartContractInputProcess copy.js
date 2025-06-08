const fs = require('fs');

// Convert DID string (e.g. did:ethr:0xabc...) to 32-byte hex with 0x prefix
function didToBytes32(did) {
  const hexPart = did.split(':').pop().toLowerCase().replace(/^0x/, '');
  return '0x' + hexPart.padStart(64, '0');
}

function toHexPrefixed(str) {
  if (str.startsWith('0x')) return str.toLowerCase();
  return '0x' + str.toLowerCase();
}

// Format array or string for registerVCRoot (all strings), using Solidity tuple style parentheses
function formatTuple(arr) {
  return '(\n  ' + arr.map(x => `"${x}"`).join(',\n  ') + '\n)';
}

// Format verifyRoot tuple, but second argument is JS array with square brackets and indentation
function formatVerifyRoot(holderDID, claimHashes, rootSalt, rootHash, vcId) {
  const formattedClaims = '[\n' + claimHashes.map(h => `    "${h}"`).join(',\n') + '\n  ]';
  return `(\n  "${holderDID}",\n  ${formattedClaims},\n  "${rootSalt}",\n  "${rootHash}",\n  "${vcId}"\n)`;
}

function prepareAndPrint(outputData) {
  for (const [credType, data] of Object.entries(outputData)) {
    if (credType === 'VP_Root') continue;

    const issuerDID = didToBytes32(data.issuerDID);
    const holderDID = didToBytes32(data.holderDID);
    const rootHash = toHexPrefixed(data.rootHash);

    const claimHashes = data.processedClaims.map(c => toHexPrefixed(c.hash));

    const rootSalt = toHexPrefixed(data.rootSalt);
    const vcId = toHexPrefixed(data.vcId);

    // Format registerVCRoot tuple (all strings)
    const registerTuple = formatTuple([issuerDID, holderDID, rootHash]);

    // Format verifyRoot tuple with claimHashes as JS array
    const verifyTuple = formatVerifyRoot(holderDID, claimHashes, rootSalt, rootHash, vcId);

    console.log(`\nCredential Type: ${credType}\n`);

    console.log('// registerVCRoot input:');
    console.log(registerTuple);

    console.log('\n// verifyRoot input:');
    console.log(verifyTuple);

    console.log('\n--------------------------------------------');
  }

  // VP_Root info if needed
  if (outputData.VP_Root) {
    const vpSalt = toHexPrefixed(outputData.VP_Root.vpSalt);
    const vpRoot = toHexPrefixed(outputData.VP_Root.vpRoot);
    const vcRoots = outputData.VP_Root.vcRoots.map(r => toHexPrefixed(r));

    console.log('\nVP Root Info:\n');
    console.log('// VP Salt:');
    console.log(`"${vpSalt}"`);
    console.log('\n// VP Root:');
    console.log(`"${vpRoot}"`);
    console.log('\n// VC Roots:');
    console.log('[\n' + vcRoots.map(r => `  "${r}"`).join(',\n') + '\n]');
  }
}

function main() {
  const raw = fs.readFileSync('output.json', 'utf8');
  const outputData = JSON.parse(raw);

  prepareAndPrint(outputData);
}

main();
