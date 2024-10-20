const { createHash, randomBytes } = require('crypto');
/**
 * with this function a key to the secret is obtained.
 * @param {string} secretKey yor secret key 
 * @returns {string} a hash
*/
const getKeyFromSecret = (secretKey) =>
{
    try
    {
        return createHash('sha256').update(secretKey).digest();
    }
    catch(err)
    {
        throw new Error('error in lek-cryptools when trying to encrypt the key: ' + err.message);
    }
};
const getIV = () => randomBytes(16);

const cipherChunk = (chunk, cipher) =>
{
    let encrypted = cipher.update(chunk, Buffer.isBuffer(chunk) ? undefined : 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

const decipherChunk = (chunk, decipher) =>
{
    let decrypted = decipher.update(chunk, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

/**
 * get a unique key
 * @param {number} num size of key 
 * @returns {string} hex key
 */
const getUniqueKeySync = (num=64) => randomBytes(num).toString('hex');

/**
 * get a unique key
 * @param {number} num size of key 
 * @returns {Promise<string>} hex key
*/

const getUniqueKey = (num=64) =>new Promise((resolve, reject) =>
{
    try
    {
        const result = getUniqueKeySync(num);
        resolve(result)
    }
    catch(err)
    {
        reject(err)
    }
})


module.exports = { getKeyFromSecret, getIV, cipherChunk, decipherChunk, getUniqueKey, getUniqueKeySync };