const { createCipheriv } = require('crypto');
const { getKeyFromSecret, getIV } = require('../tools');
const ERRORS = require('../errors');

/**
 * @typedef {import("@/lib/types/index").CipherSyncFunction} CipherSyncFunction
 * @typedef {import("@/lib/types/index").CipherFunction} CipherFunction
 */

/** @type {CipherSyncFunction} */
const cipherSync = (data, secretKey) =>
{
    try
    {
        const key = getKeyFromSecret(secretKey);
        if (key.length !== 32) throw new Error('Invalid key. system need a 32 bits key');

        const dataIsBuff = Buffer.isBuffer(data);
        const dataBuff = dataIsBuff ? data : Buffer.from(data);

        const iv = getIV();
        const cipher_ = createCipheriv('aes-256-cbc', key, iv);
        const ciphred = Buffer.concat([cipher_.update(dataBuff), cipher_.final()]);

        const bufferResult = Buffer.concat([iv, ciphred]);
        //@ts-ignore
        return dataIsBuff ? bufferResult : bufferResult.toString('hex');
    }
    catch (err)
    {
        throw ERRORS.CIPHER(err);
    }
};

/** @type {CipherFunction} */
const cipher = (data, secretKey) => new Promise((resolve, reject) =>
{
    try
    {
        const result = cipherSync(data, secretKey);
        resolve(result);
    }
    catch (err)
    {
        reject(err);
    }
});

module.exports = { cipherSync, cipher };