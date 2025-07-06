const { createDecipheriv } = require('crypto');
const { getKeyFromSecret, isHex } = require('../tools');
const ERRORS = require('../errors');

/**
 * @typedef {import("../../lib/types/index").DecipherSyncFunction} DecipherSyncFunction
 * @typedef {import("../../lib/types/index").DecipherFunction} DecipherFunction
 */

/** @type {DecipherSyncFunction} */
const decipherSync = (encrypted, secretKey, mode="cbc") => {
    try
    {
        const encryptedIsBuff = Buffer.isBuffer(encrypted);
        if(!encryptedIsBuff && !isHex(encrypted))
        {
            throw new Error("String key is not hexagecimal key");
        }
        
        const chphredBuffer = encryptedIsBuff ? encrypted : Buffer.from(encrypted, 'hex');

        if (chphredBuffer.length < 16) throw new Error('invalid format');


        if(mode === "cbc")
        {
            const iv = chphredBuffer.slice(0, 16);            
            const data = chphredBuffer.slice(16);
    
            const key = getKeyFromSecret(secretKey);
            if (key.length !== 32) throw new Error('Invalid key length');
    
            const decipher_ = createDecipheriv('aes-256-cbc', key, iv);
            //@ts-ignore
            const result = Buffer.concat([decipher_.update(data), decipher_.final()]);
            //@ts-ignore
            return encryptedIsBuff ? result : result.toString();
        }
        else
        {
            const iv = chphredBuffer.slice(0, 12);
            const authTag = chphredBuffer.slice(-16);
            const data = chphredBuffer.slice(12, chphredBuffer.length - 16);
    
            const key = getKeyFromSecret(secretKey);
            if (key.length !== 32) throw new Error('Invalid key length');
    
            const decipher_ = createDecipheriv('aes-256-gcm', key, iv);
            decipher_.setAuthTag(Buffer.from(authTag));
            //@ts-ignore
            const result = Buffer.concat([decipher_.update(data), decipher_.final()]);
            //@ts-ignore
            return encryptedIsBuff ? result : result.toString();
        }
        
    }
    catch (err)
    {
        throw ERRORS.DECIPHER(err);
    }
};

/** @type {DecipherFunction} */
const decipher = (encrypted, secretKey, mode="cbc") => new Promise((resolve, reject) =>
{
    try
    {
        const result = decipherSync(encrypted, secretKey, mode);
        resolve(result);
    }
    catch (err)
    {
        reject(err);
    }
});

module.exports = { decipher, decipherSync };