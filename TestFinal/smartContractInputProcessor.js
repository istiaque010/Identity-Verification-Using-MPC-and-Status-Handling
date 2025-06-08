const fs = require('fs');

// Helpers to format DIDs and hex strings
function didToBytes32(did) {
  const hexPart = did.split(':').pop().toLowerCase().replace(/^0x/, '');
  return '0x' + hexPart.padStart(64, '0');
}

function toHexPrefixed(str) {
  if (str.startsWith('0x')) return str.toLowerCase();
  return '0x' + str.toLowerCase();
}

function formatRegisterTuple(arr) {
  return '(\n  ' + arr.map(x => `"${x}"`).join(',\n  ') + '\n)';
}

function formatVerifyTuple(holderDID, claimHashes, rootSalt, rootHash, vcId) {
  const claimsFormatted = '[\n' + claimHashes.map(h => `    "${h}"`).join(',\n') + '\n  ]';
  return `(\n  "${holderDID}",\n  ${claimsFormatted},\n  "${rootSalt}",\n  "${rootHash}",\n  "${vcId}"\n)`;
}

function prepareTextOutput(outputData) {
  let text = '';

  for (const [credType, data] of Object.entries(outputData)) {
    if (credType === 'VP_Root') continue;

    const issuerDID = didToBytes32(data.issuerDID);
    const holderDID = didToBytes32(data.holderDID);
    const rootHash = toHexPrefixed(data.rootHash);
    const claimHashes = data.processedClaims.map(c => toHexPrefixed(c.hash));
    const rootSalt = toHexPrefixed(data.rootSalt);
    const vcId = toHexPrefixed(data.vcId);

    text += `✅ registerVCRoot(...) for ${credType}\n`;
    text += `solidity\n`;
    text += formatRegisterTuple([issuerDID, holderDID, rootHash]) + '\n\n';

    text += `✅ verifyRoot(...) for ${credType}\n`;
    text += `solidity\n`;
    text += formatVerifyTuple(holderDID, claimHashes, rootSalt, rootHash, vcId) + '\n\n';

    text += '------------------------------------------------------------\n\n';
  }

  // Optionally add VP_Root info if present
  if (outputData.VP_Root) {
    const vpSalt = toHexPrefixed(outputData.VP_Root.vpSalt);
    const vpRoot = toHexPrefixed(outputData.VP_Root.vpRoot);
    const vcRoots = outputData.VP_Root.vcRoots.map(r => toHexPrefixed(r));

    text += `VP Root Info:\n`;
    text += `VP Salt:\n"${vpSalt}"\n\n`;
    text += `VP Root:\n"${vpRoot}"\n\n`;
    text += `VC Roots:\n[\n` + vcRoots.map(r => `  "${r}"`).join(',\n') + '\n]\n\n';
  }

  return text;
}

function main() {
  const raw = fs.readFileSync('output.json', 'utf8');
  const outputData = JSON.parse(raw);

  const textOutput = prepareTextOutput(outputData);

  fs.writeFileSync('smartcontractinput.txt', textOutput, 'utf8');
  console.log('✅ smartcontractinput.txt generated with formatted Solidity input!');
}

main();
