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


module.exports = { getKeyFromSecret, getIV, getUniqueKey, getUniqueKeySync };