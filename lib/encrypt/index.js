const { hash, genSalt, hashSync, genSaltSync } = require('bcryptjs');

/**
 * @typedef {import("@/lib/types/index").EncryptFunction} EncryptFunction
 * @typedef {import("@/lib/types/index").EncryptSyncFunction} EncryptSyncFunction
 */

/** @type {EncryptFunction} */
const encrypt = async (data, num = 10) => hash(data, await genSalt(num));

/** @type {EncryptSyncFunction} */
const encryptSync = (data, num = 10) => hashSync(data, genSaltSync(num));

module.exports = { encrypt, encryptSync };
