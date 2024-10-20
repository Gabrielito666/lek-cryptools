const { hash, genSalt } = require('bcryptjs');
/**
 * encrypt a key
 * @param {string} data string to encrypt
 * @param {number} [num=10] number from salt
 * @returns {string} a hash
*/
const encrypt = async(data, num=10) => hash(data, await genSalt(num));
module.exports = encrypt;