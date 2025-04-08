// utils/jwtUtils.js
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const secretKey = '90580b16ded5e073a24ceb67180f82bacfd7c49d69e63b0604831a7d0d7185530cc3a5e5b4fb36ac606da08025bb386b48aa437cc6ba45b91eafbdbd44bb69b1'; // For signing JWT
const encryptionKey = crypto.randomBytes(32); // 32 bytes = 256 bits
const iv = crypto.randomBytes(16); // Initialization vector

const encrypt = (payload) => {
  // 1. Sign the JWT token
  const token = jwt.sign(payload, secretKey, { expiresIn: '1h' });

  // 2. Encrypt the token
  const cipher = crypto.createCipheriv('aes-256-cbc', encryptionKey, iv);
  let encrypted = cipher.update(token, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  // Combine iv and encrypted token (needed for decryption)
  return iv.toString('hex') + ':' + encrypted;
};

const decrypt = (encryptedToken) => {
  // 1. Split IV and the encrypted data
  const parts = encryptedToken.split(':');
  const ivBuffer = Buffer.from(parts[0], 'hex');
  const encrypted = parts[1];

  // 2. Decrypt
  const decipher = crypto.createDecipheriv('aes-256-cbc', encryptionKey, ivBuffer);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  // 3. Verify and decode JWT
  const payload = jwt.verify(decrypted, secretKey);
  return payload;
};

module.exports = {
  encrypt,
  decrypt
};
