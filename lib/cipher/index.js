const { createCipheriv } = require('crypto')
const { cipherChunk, getKeyFromSecret, getIV } = require('../tools');

/**
 * function to encrypt a string or buffer
 * @param {string|Buffer} data string or buffer to cipher
 * @param {string} secretKey secret key to decipher later
 * @returns {string|Buffer} ciphred data
*/
const cipher = (data, secretKey) =>
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
        throw new Error('error in lek-cryptools when trying to encrypt the key: ' + err.message);
    }
};

module.exports = cipher;