const { createDecipheriv } = require('crypto')
const { decipherChunk, getKeyFromSecret } = require('../tools');

/**
 * function to decrypt a string or buffer
 * @param {string|Buffer} encrypted pre-ciphred data
 * @param {string} secretKey key to decipher
 * @returns {string|buffer} data
*/
const decipher = (encrypted, secretKey) => {
    try
    {
        const key = getKeyFromSecret(secretKey);
        const parts = encrypted.split(':');
        const iv = Buffer.from(parts.shift(), 'hex');
        const decipher_ = createDecipheriv('aes-256-cbc', key, iv);
        const encryptedText = parts.join(':');
        return decipherChunk(encryptedText, decipher_);
    }
    catch (err)
    {
        throw new Error('error in lek-cryptools when trying to decrypt the key: ' + err.message);
    }
};
module.exports = decipher;