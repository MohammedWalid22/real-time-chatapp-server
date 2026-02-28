const crypto = require('crypto');
const NodeRSA = require('node-rsa');

// Constants
const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32; // 256 bits
const IV_LENGTH = 16;  // 128 bits
const TAG_LENGTH = 16; // 128 bits

// Generate new encryption key (for Room creation)
exports.generateEncryptionKey = () => {
  return crypto.randomBytes(32).toString('hex');
};

// Generate RSA key pair for user
exports.generateKeyPair = () => {
  const key = new NodeRSA({ b: 2048 });
  return {
    publicKey: key.exportKey('public'),
    privateKey: key.exportKey('private')
  };
};

// Encrypt message with AES-256-GCM
exports.encryptMessage = (message, keyHex) => {
  // Validate key exists
  if (!keyHex) {
    throw new Error('Encryption key is required');
  }
  
  // If key is hex string, convert to buffer directly
  // If not, derive key using scrypt
  let key;
  if (keyHex.length === 64) {
    // Already a 32-byte hex string
    key = Buffer.from(keyHex, 'hex');
  } else {
    // Derive key from string
    key = crypto.scryptSync(keyHex, 'salt', KEY_LENGTH);
  }
  
  const iv = crypto.randomBytes(IV_LENGTH);
  
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  
  let encrypted = cipher.update(message, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  const authTag = cipher.getAuthTag();
  
  // Return as string format for storage
  return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
};

// Decrypt message
exports.decryptMessage = (encryptedData, keyHex) => {
  // Validate inputs
  if (!keyHex) {
    throw new Error('Encryption key is required');
  }
  
  if (!encryptedData || typeof encryptedData !== 'string') {
    throw new Error('Invalid encrypted data');
  }
  
  // Parse the encrypted data format: iv:authTag:encrypted
  const parts = encryptedData.split(':');
  if (parts.length !== 3) {
    throw new Error('Invalid encrypted data format');
  }
  
  const [ivHex, authTagHex, encrypted] = parts;
  
  // Prepare key
  let key;
  if (keyHex.length === 64) {
    key = Buffer.from(keyHex, 'hex');
  } else {
    key = crypto.scryptSync(keyHex, 'salt', KEY_LENGTH);
  }
  
  const iv = Buffer.from(ivHex, 'hex');
  
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
  
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
};

// Encrypt AES key with RSA public key
exports.encryptKey = (aesKey, publicKey) => {
  const key = new NodeRSA(publicKey);
  return key.encrypt(aesKey, 'base64');
};

// Decrypt AES key with RSA private key
exports.decryptKey = (encryptedKey, privateKey) => {
  const key = new NodeRSA(privateKey);
  return key.decrypt(encryptedKey, 'utf8');
};