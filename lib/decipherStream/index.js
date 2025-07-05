const { createDecipheriv } = require('crypto');
const { getKeyFromSecret } = require('../tools');
const { pipeline, Transform } = require('stream');
const ERRORS = require('../errors');

/**
 * @typedef {import("../../lib/types/index").DecipherStreamFunction} DecipherStreamFunction
 */

/** @type {DecipherStreamFunction} */
const decipherStream = (inputStream, outputStream, secretKey, mode="cbc") => new Promise((resolve, reject) =>
{
    try
    {
        
        const STATES = {
            iv: Buffer.alloc(0),
            tempBuffer: Buffer.alloc(0),
            ivIsReconstructed: false,
            decipher_: undefined,
        };
        const ivLength = mode === "cbc" ? 16 : 12;

        const key = getKeyFromSecret(secretKey);
        if (key.length !== 32) throw new Error('Invalid key. System needs a 32-byte key');

        const decipherTransform = new Transform
        ({
            transform(chunk, encoding, callback)
            {
                if (!STATES.ivIsReconstructed)
                {
                    const bitsRest = ivLength - STATES.iv.length;

                    if (chunk.length > bitsRest)
                    {
                        //If iv are reconstructed first and unique time
                        STATES.ivIsReconstructed = true;
                        const rest = chunk.slice(0, bitsRest);
                        const firstData = chunk.slice(bitsRest);
                        const iv = Buffer.concat([STATES.tempBuffer, rest]);

                        if(mode === "cbc")
                        {
                            STATES.decipher_ = createDecipheriv('aes-256-cbc', key, iv);
                        }
                        else
                        {
                            STATES.decipher_ = createDecipheriv('aes-256-gcm', key, iv);
                        }

                        STATES.tempBuffer = firstData;

                        callback();
                    }
                    else
                    {
                        //If iv are not reconstructed yet
                        STATES.tempBuffer = Buffer.concat([STATES.tempBuffer, chunk]);
                        callback();
                    }
                }
                else
                {
                    //If iv are reconstructed and we can decipher data
                    if(STATES.tempBuffer.length + chunk.length > 16)
                    {
                        //If are more than 16 bytes
                        const allData = Buffer.concat([STATES.tempBuffer, chunk]);
                        const firstData = allData.slice(0, STATES.tempBuffer.length - 16);
                        const last16Bytes = allData.slice(-16);
                        STATES.tempBuffer = last16Bytes;

                        const deciphred = STATES.decipher_.update(firstData);
                        callback(null, deciphred);
                    }
                    else
                    {
                        //If are less than 16 bytes
                        STATES.tempBuffer = Buffer.concat([STATES.tempBuffer, chunk]);
                        callback();    
                    }
                }
            },
            flush(callback)
            {
                try
                {
                    if(mode === "gcm") 
                    {
                        if(STATES.tempBuffer.length < 16)
                        {
                            throw ERRORS.DECIPHER(new Error('Invalid format. Expected 16 bytes for auth tag in GCM mode'));
                        }
                        const authTag = STATES.tempBuffer.slice(-16);
                        const finalData = STATES.tempBuffer.slice(0, -16);
                        
                        const finalDeciphred = STATES.decipher_.update(finalData);

                        STATES.decipher_.setAuthTag(authTag);
                        const finalBuffer = STATES.decipher_.final();
                        callback(null, Buffer.concat([finalDeciphred, finalBuffer]));
                    }
                    else
                    {
                        const lastDecipher = STATES.decipher_.update(STATES.tempBuffer);
                        const finalBuffer = STATES.decipher_.final();
                        callback(null, Buffer.concat([lastDecipher, finalBuffer]));
                    }
                }
                catch (err)
                {
                    callback(err);
                }
            }
        });

        const errHandler = (err) =>
        {
            if (err) reject(ERRORS.DECIPHER(err));
            else resolve();
        };

        pipeline(inputStream, decipherTransform, outputStream, errHandler);
    }
    catch (err)
    {
        reject(ERRORS.DECIPHER(err));
    }
});

module.exports = decipherStream;