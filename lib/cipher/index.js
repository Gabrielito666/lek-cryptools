const { createCipheriv } = require('crypto');
const { getKeyFromSecret, getIV } = require('../tools');
const ERRORS = require('../errors');

/**
 * @typedef {import("../../lib/types/index").CipherSyncFunction} CipherSyncFunction
 * @typedef {import("../../lib/types/index").CipherFunction} CipherFunction
*/

/** @type {CipherSyncFunction} */
const cipherSync = (data, secretKey, mode="cbc") =>
{
    try
    {
        const key = getKeyFromSecret(secretKey);
        if (key.length !== 32) throw new Error('Invalid key. system need a 32 bits key');

        const dataIsBuff = Buffer.isBuffer(data);
        const dataBuff = dataIsBuff ? data : Buffer.from(data);

        const iv = getIV(mode);

        if(mode === "cbc")
        {
            const cipher_ = createCipheriv('aes-256-'+ mode, key, iv);
            const ciphred = Buffer.concat([cipher_.update(dataBuff), cipher_.final()]);
    
            const bufferResult = Buffer.concat([iv, ciphred]);
            //@ts-ignore
            return dataIsBuff ? bufferResult : bufferResult.toString('hex');
        }
        else
        {
            const cipher_ = createCipheriv('aes-256-gcm', key, iv);
            const ciphred = Buffer.concat([cipher_.update(dataBuff), cipher_.final()]);
            const authTag = cipher_.getAuthTag();
            const bufferResult = Buffer.concat([iv, ciphred, authTag]);
            //@ts-ignore
            return dataIsBuff ? bufferResult : bufferResult.toString('hex');
        }
    }
    catch (err)
    {
        throw ERRORS.CIPHER(err);
    }
};

/** @type {CipherFunction} */
const cipher = (data, secretKey, mode="cbc") => new Promise((resolve, reject) =>
{
    try
    {
        const result = cipherSync(data, secretKey, mode);
        resolve(result);
    }
    catch (err)
    {
        reject(err);
    }
});

module.exports = { cipherSync, cipher };