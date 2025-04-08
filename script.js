const { encrypt, decrypt } = require('./utils/jwtUtils');

const myPayload = { userId: 123, role: 'therapist' };

const encryptedToken = encrypt(myPayload);
console.log('Encrypted Token:', encryptedToken);

const decryptedPayload = decrypt(encryptedToken);
console.log('Decrypted Payload:', decryptedPayload); // Should print: { userId: 123, role: 'therapist', iat:..., exp:... }
