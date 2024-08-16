const crypto = require('crypto');

// Criptografia AES-256
function encrypt(text) {
    const algorithm = 'aes-256-cbc';
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);

    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    return {
        iv: iv.toString('hex'),
        encryptedData: encrypted,
        key: key.toString('hex')
    };
}

function decrypt(encryptedData, key, iv) {
    const algorithm = 'aes-256-cbc';
    const decipher = crypto.createDecipheriv(algorithm, Buffer.from(key, 'hex'), Buffer.from(iv, 'hex'));

    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
}

const data = "Informação sensível";
const encrypted = encrypt(data);
console.log("Encrypted:", encrypted);

const decrypted = decrypt(encrypted.encryptedData, encrypted.key, encrypted.iv);
console.log("Decrypted:", decrypted);
