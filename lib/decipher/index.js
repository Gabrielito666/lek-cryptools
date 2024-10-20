const { createDecipheriv } = require('crypto')
const { decipherChunk, getKeyFromSecret } = require('../tools');
const ERRORS = require('../errors');

/**
 * sync function to decrypt a string or buffer
 * @param {string|Buffer} encrypted pre-ciphred data
 * @param {string} secretKey key to decipher
 * @returns {string|buffer} data
*/
const decipherSync = (encrypted, secretKey) => {
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
        console.log(err)
        throw ERRORS.DECIPHER
    }
};

/**
 * async function to decrypt a string or buffer
 * @param {string|Buffer} encrypted pre-ciphred data
 * @param {string} secretKey key to decipher
 * @returns {Promise<string|buffer>} data
*/
const decipher = (encrypted, secretKey) => new Promise((resolve, reject) =>
{
    try
    {
        const result = decipherSync(encrypted, secretKey);
        resolve(result);
    }
    catch(err)
    {
        reject(err)
    }
});

module.exports = {decipher, decipherSync};