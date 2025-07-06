const { createHash, randomBytes } = require('crypto');

/**
 * @typedef {import("../../lib/types/index").GetKeyFromSecretFunction} GetKeyFromSecretFunction
 * @typedef {import("../../lib/types/index").GetIVFunction} GetIVFunction
 * @typedef {import("../../lib/types/index").GetUniqueKeyFunction} GetUniqueKeyFunction
 * @typedef {import("../../lib/types/index").GetUniqueKeySyncFunction} GetUniqueKeySyncFunction
 * @typedef {import("../../lib/types/index").IsHexFunction} IsHexFunction 
 */

/** @type {GetKeyFromSecretFunction} */
const getKeyFromSecret = (secretKey) => {
    try {
        return createHash('sha256').update(secretKey).digest();
    } catch (err) {
        throw new Error('error in lek-cryptools when trying to encrypt the key: ' + err.message);
    }
};

/** @type {GetIVFunction} */
const getIV = (mode="cbc") => randomBytes(mode === "cbc" ? 16 : 12);

/** @type {GetUniqueKeySyncFunction} */
const getUniqueKeySync = (num = 64) => randomBytes(num).toString('hex');

/** @type {GetUniqueKeyFunction} */
const getUniqueKey = (num = 64) => new Promise((resolve, reject) => {
    try {
        const result = getUniqueKeySync(num);
        resolve(result);
    } catch (err) {
        reject(err);
    }
});

/**@type {IsHexFunction}*/
const isHex = str => typeof str === 'string' && /^[0-9a-fA-F]*$/.test(str) && str.length % 2 === 0;

module.exports = { getKeyFromSecret, getIV, getUniqueKey, getUniqueKeySync, isHex };