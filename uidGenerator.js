// src/utils/uidGenerator.js
const { v4: uuidv4 } = require('uuid');  // Importing UUID v4 from the 'uuid' package

// Function to generate a unique UID
function generateUID() {
  return uuidv4();  // Generate a unique ID using UUID v4
}

module.exports = { generateUID };
