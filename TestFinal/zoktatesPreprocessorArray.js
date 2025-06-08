const crypto = require("crypto");

// Convert buffer to array of u32 (big-endian)
function bufferToU32Array(buf, totalWords) {
    const result = [];
    for (let i = 0; i < totalWords; i++) {
        const slice = buf.slice(i * 4, i * 4 + 4);
        result.push(slice.readUInt32BE(0));
    }
    return result;
}

// Prepare 64-byte buffer with SHA-256 padding for short messages
function padToSHA256Block(str) {
    const strBuf = Buffer.from(str, 'utf8');
    const lenBits = strBuf.length * 8;

    const padded = Buffer.alloc(64); // 512 bits
    strBuf.copy(padded, 0);          // Copy original input
    padded[strBuf.length] = 0x80;    // Append 0x80 (10000000)
    padded.writeUInt32BE(lenBits, 60); // Message length in bits (big-endian)

    return padded;
}

// Main processor for array of strings
function preprocessZoKratesArray(inputs) {
    const paddedList = [];
    const hashList = [];

    console.log(`✅ Input Format for array:`);
    inputs.forEach((inputStr, idx) => {
        const paddedBuffer = padToSHA256Block(inputStr);
        const paddedU32 = bufferToU32Array(paddedBuffer, 16);
        const hashBuffer = crypto.createHash('sha256').update(inputStr).digest();
        const hashU32 = bufferToU32Array(hashBuffer, 8);

        paddedList.push(paddedU32.map(String));
        hashList.push(hashU32.map(String));

        console.log(`\n🔹 Entry ${idx + 1}: "${inputStr}"`);
        console.log("🟩 padded (u32[16]):");
        console.log(JSON.stringify(paddedU32.map(String), null, 2));
        console.log("🟦 expected_hash (u32[8]):");
        console.log(JSON.stringify(hashU32.map(String), null, 2));
    });

    // Final arrays for ZoKrates
    console.log(`\n🟢 Full ZoKrates-compatible input arrays:\n`);
    console.log("padded array (private input):");
    console.log(JSON.stringify(paddedList, null, 2));
    console.log("\nexpected_hashes array (public input):");
    console.log(JSON.stringify(hashList, null, 2));
}

// Example usage
const inputArray = ["Adam", "Doctor", "19800101"];
preprocessZoKratesArray(inputArray);
