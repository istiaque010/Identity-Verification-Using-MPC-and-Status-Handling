const crypto = require('crypto');

// Generic brute-force function
function bruteForceHash(targetHex, bufferParts, iterations = 1_000_000) {
  const start = process.hrtime.bigint();

  for (let i = 0; i < iterations; i++) {
    const salt = crypto.randomBytes(32);
    const combined = Buffer.concat([...bufferParts, salt]);
    const hash = crypto.createHash('sha256').update(combined).digest('hex');
    if (hash === targetHex.toLowerCase()) {
      const end = process.hrtime.bigint();
      return {
        matched: true,
        attempts: i + 1,
        timeMs: Number(end - start) / 1e6,
        salt: salt.toString('hex'),
        hash
      };
    }
  }

  const end = process.hrtime.bigint();
  return {
    matched: false,
    attempts: iterations,
    timeMs: Number(end - start) / 1e6
  };
}

// Inputs
const preRoots = [
  '08d44410052055d0d5220a24020aa7247192b6f3f9b43815e5626c123c7f8d49',
  'dc93a5e41de873beb7cb7def143ca44a1bba5143e4b81257c93f337e332da173',
  '0cc4b7b798f4cbaa607934a7db651ccc3df0e98c2591351ccbc46775394ff0b2'
];

const expectedRoots = [
  '546444071fe506bc07018a4e1d6922e9f6c4853b31bcf3a2bdeec366f8e89ec8',
  '13a2a43463a8b9f2b20b37f9c00081dff295bc2f69746ca1489470a7060a9fa3',
  'dc7b9ba847d5ca7d6c5957b219184d3c4940c9a417b83b37626bb488383ad6b5'
];

const expectedVpRoot = 'c1a5cf51f806e4ee63a7405cae8bb09596222a17f2dbeaab5c8eda6522c2eb45';

// Run full test
(async () => {
  const vcResults = [];

  // Step 1: Brute-force VC roots
  for (let i = 0; i < 3; i++) {
    console.log(`\n🔍 Brute-forcing VC${i + 1}...`);
    const result = bruteForceHash(expectedRoots[i], [Buffer.from(preRoots[i], 'hex')]);
    console.log(result);
    vcResults.push(result);
  }

  // Step 2: Brute-force VP root — always attempt it
  const vcRootBuffers = vcResults.map((r, i) =>
    Buffer.from(r.matched ? r.hash : expectedRoots[i], 'hex')
  );

  console.log(`\n🔍 Brute-forcing VP root (regardless of VC match status)...`);
  const vpResult = bruteForceHash(expectedVpRoot, vcRootBuffers);
  console.log(vpResult);
})();
