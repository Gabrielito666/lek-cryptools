const { createCipheriv } = require('crypto')
const { cipherChunk, getKeyFromSecret, getIV } = require('../tools');
const ERRORS = require('../errors');

/**
 * sync function to encrypt a string or buffer
 * @param {string|Buffer} data string or buffer to cipher
 * @param {string} secretKey secret key to decipher later
 * @returns {string|Buffer} ciphred data
*/
const cipherSync = (data, secretKey) =>
{
    try
    {
        const key = getKeyFromSecret(secretKey);
        const iv = getIV();
        const cipher_ = createCipheriv('aes-256-cbc', key, iv);
        return iv.toString('hex') + ':' + cipherChunk(data, cipher_);
    }
    catch (err)
    {
        throw ERRORS.CIPHER;
    }
};

/**
 * async function to encrypt a string or buffer
 * @param {string|Buffer} data string or buffer to cipher
 * @param {string} secretKey secret key to decipher later
 * @returns {Promise<string|Buffer>} ciphred data
*/
const cipher = (data, secretKey) => new Promise((resolve, reject) =>
{
    try
    {
        const result = cipherSync(data, secretKey);
        resolve(result);
    }
    catch(err)
    {
        reject(err)
    }
})

module.exports = { cipherSync, cipher };