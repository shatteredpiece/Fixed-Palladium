const crypto = require('crypto');
const { logError } = require('./logs');

// Set a 32-byte (256-bit) encryption key
const encryptionKey = process.env.ENCRYPTION_KEY; // securely store

// Function to generate a 16-byte IV for AES encryption
function generateIv() {
  return crypto.randomBytes(16).toString('hex');
}

// Function to encrypt plaintext
function encrypt(password) {
  try {
    if (!encryptionKey || encryptionKey === "") {
      console.warn('No encryption key, password will not be encrypted');
      return password;
    }

    // Generate IV and ensure the key is 32 bytes
    const iv = generateIv();
    const key = Buffer.from(encryptionKey, 'hex');
    if (key.length !== 32) {
      throw new Error("Encryption key must be 32 bytes for AES-256");
    }

    // Encrypt the plaintext
    const cipher = crypto.createCipheriv('aes-256-cbc', key, Buffer.from(iv, 'hex'));
    let encryptedData = cipher.update(password, 'utf8', 'hex');
    encryptedData += cipher.final('hex');

    // Return both IV and encrypted data for decryption
    return { iv: iv, encryptedData: encryptedData };
  } catch (error) {
    logError('Error in encrypt', error)
    return null;
  }
}

// Function to decrypt the encrypted data
function decrypt(encrypted) {
  try {
    if (!encryptionKey || encryptionKey === "") {
      console.warn('No encryption key, encrypted data will not be decrypted');
      return encrypted;
    }

    // Validate the encrypted object structure
    if (!encrypted || !encrypted.iv || !encrypted.encryptedData) {
      console.warn('Invalid encrypted data format');
      return null;
    }

    // Ensure the encryption key is 32 bytes
    const key = Buffer.from(encryptionKey, 'hex');
    if (key.length !== 32) {
      throw new Error("Encryption key must be 32 bytes for AES-256");
    }

    // Decrypt the encrypted data
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, Buffer.from(encrypted.iv, 'hex'));
    let decrypted = decipher.update(encrypted.encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  } catch (error) {
    console.error('Error in decrypt:', error);
    return null;
  }
}

module.exports = {
    encrypt,
    decrypt
  };
