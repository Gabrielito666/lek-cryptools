const { createDecipheriv } = require('crypto')
const { getKeyFromSecret } = require('../tools');
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
        const encryptedIsBuff = Buffer.isBuffer(encrypted);
        const chphredBuffer = encryptedIsBuff ? encrypted : Buffer.from(encrypted, 'hex');

        if(chphredBuffer.length < 16) throw new Error('invalid format');

        const iv = chphredBuffer.slice(0, 16);
        const data = chphredBuffer.slice(16);

        const key = getKeyFromSecret(secretKey);
        if (key.length !== 32) throw new Error('Invalid key length');

        const decipher_ = createDecipheriv('aes-256-cbc', key, iv);

        const result = Buffer.concat([decipher_.update(data), decipher_.final()]);
        return encryptedIsBuff ? result : result.toString();
    }
    catch (err)
    {
        throw ERRORS.DECIPHER(err)
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