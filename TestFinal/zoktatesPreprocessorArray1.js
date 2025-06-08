const crypto = require("crypto");
const fs = require("fs");

// Convert buffer to array of u32 (big-endian)
function bufferToU32Array(buf, totalWords) {
    const result = [];
    for (let i = 0; i < totalWords; i++) {
        const slice = buf.slice(i * 4, i * 4 + 4);
        result.push(slice.readUInt32BE(0));
    }
    return result;
}

// Pad input string into a 64-byte SHA256 input block
function padToSHA256Block(str) {
    const strBuf = Buffer.from(str, 'utf8');
    const lenBits = strBuf.length * 8;
    const padded = Buffer.alloc(64);
    strBuf.copy(padded, 0);
    padded[strBuf.length] = 0x80;
    padded.writeUInt32BE(lenBits, 60);
    return padded;
}

// Preprocess multiple input strings
function preprocessZoKratesArray(inputs) {
    const padded = [];
    const expected_hashes = [];

    inputs.forEach((inputStr) => {
        const paddedBuffer = padToSHA256Block(inputStr);
        const paddedU32 = bufferToU32Array(paddedBuffer, 16);
        const hashBuffer = crypto.createHash('sha256').update(inputStr).digest();
        const hashU32 = bufferToU32Array(hashBuffer, 8);

        padded.push(paddedU32.map(String));
        expected_hashes.push(hashU32.map(String));
    });

    const output = {
        "padded (private input)": padded,
        "expected_hashes (public input)": expected_hashes
    };

    fs.writeFileSync("zokrates_inputs.json", JSON.stringify(output, null, 2), "utf8");
    console.log("✅ ZoKrates input saved to zokrates_inputs.json");
}

// Example input values
//const inputArray = ["Adam", "Doctor", "19800101"];

//const inputArray = ["John Doe", "1990-01-01", "NID123456789", "CountryX", "3f8a1c7e9d4b2f65a1b0c9e7d3f5a8b2"];
//const inputArray = ["John Doe", "1990-01-01", "a7d4e982f1b36c5d49e7203fba58d1e0"];
//const inputArray = [ "1990-01-01", "f39b6a1d0c8e45b2d7f903e4a16c2f87"];
const inputArray = ["John Doe", "1990-01-01", "NID123456789",  "5e3c7f2b1a9d6840e8f2053c7b4a91d6"];



preprocessZoKratesArray(inputArray);
