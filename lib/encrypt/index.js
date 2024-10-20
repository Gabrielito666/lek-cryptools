const { hash, genSalt, hashSync, genSaltSync } = require('bcryptjs');
/**
 * async encrypt a key
 * @param {string} data string to encrypt
 * @param {number} [num=10] number from salt
 * @returns {Promise<string>} a hash
*/
const encrypt = async(data, num=10) => hash(data, await genSalt(num));

/**
 * sync encrypt a key
 * @param {string} data string to encrypt
 * @param {number} [num=10] number from salt
 * @returns {string} a hash
*/
const encryptSync = (data, num=10) => hashSync(data, genSaltSync(num));

module.exports = {encrypt, encryptSync};