const crypto = require('crypto');

// Generate secure random tokens
const generateSecureToken = (length = 32) => {
  return crypto.randomBytes(length).toString('hex');
};

// Hash sensitive data
const hashData = (data) => {
  return crypto.createHash('sha256').update(data).digest('hex');
};

// Constant time comparison (prevent timing attacks)
const secureCompare = (a, b) => {
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
};

module.exports = {
  generateSecureToken,
  hashData,
  secureCompare
};