const crypto = require('crypto');

// Step 1: Encode "Adam" as UTF-8
const input = Buffer.from("Adam", "utf8"); // 0x41 64 61 6D

// Step 2: Hash with SHA-256
const hash = crypto.createHash('sha256').update(input).digest();

// Step 3: Print full hash and split into u32 array
console.log("SHA-256 (hex):", hash.toString('hex'));

// Convert to u32[8] (big-endian)
const u32 = [];
for (let i = 0; i < 32; i += 4) {
  u32.push(hash.readUInt32BE(i));
}
console.log("SHA-256 as u32[8]:", u32.map(n => '0x' + n.toString(16)));




