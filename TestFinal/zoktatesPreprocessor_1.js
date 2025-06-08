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

    // Last 8 bytes = message length in bits (big-endian)
    padded.writeUInt32BE(lenBits, 60); // high word is 0 for short messages

    return padded;
}

// Main preprocessor
function preprocessZoKratesInput(inputStr) {
    const paddedBuffer = padToSHA256Block(inputStr);
    const paddedU32 = bufferToU32Array(paddedBuffer, 16); // u32[16]
    const hashBuffer = crypto.createHash('sha256').update(inputStr).digest();
    const hashU32 = bufferToU32Array(hashBuffer, 8);       // u32[8]

    console.log("✅ Input Format for \"" + inputStr + "\"");
    console.log("Use this in ZoKrates UI:\n");

    console.log("🟩 padded (private):\n");
    console.log(JSON.stringify(paddedU32.map(String), null, 2));

    console.log("\n🟦 expected_hash (public):\n");
    console.log(JSON.stringify(hashU32.map(String), null, 2));

    console.log("\n🧾 Raw Details:");
    console.log("Original input string:", inputStr);
    console.log("Padded (hex):", paddedBuffer.toString("hex"));
    console.log("SHA-256 Hash (hex):", hashBuffer.toString("hex"));
}

// Example usage
preprocessZoKratesInput("Japan");
