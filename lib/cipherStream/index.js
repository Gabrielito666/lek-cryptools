const { createCipheriv, Cipher } = require('crypto');
const { getIV, getKeyFromSecret } = require('../tools');
const { Transform, pipeline } = require('stream');
const ERRORS = require('../errors');

/**
 * @typedef {import("../../lib/types/index").CipherStreamFunction} CipherStreamFunction
 */

/** @type {CipherStreamFunction} */
const cipherStream = (inputStream, outputStream, secretKey, mode="cbc") => new Promise((resolve, reject) =>
{
    try
    {
        const key = getKeyFromSecret(secretKey);
        if (key.length !== 32) throw new Error('Invalid key. system need a 32 bits key');

        const iv = getIV(mode);
        outputStream.write(iv);

        const refs = {};
        if (mode === "cbc")
        {
            refs.cipher_ = createCipheriv('aes-256-cbc', key, iv);
        }
        else
        {
            refs.cipher_ = createCipheriv('aes-256-gcm', key, iv);
        }

        const cipherTransform = new Transform
        ({
            transform(chunk, encoding, callback) {
                const ciphred = refs.cipher_.update(chunk);
                callback(null, ciphred);
            },
            flush(callback) {
                try
                {
                    const finalDtaBuff = refs.cipher_.final();
                    if(mode === "cbc")
                    {
                        callback(null, finalDtaBuff);
                    }
                    else
                    {
                        const authTagBuff = refs.cipher_.getAuthTag();
                        callback(null, Buffer.concat([finalDtaBuff, authTagBuff]));
                    }
                }
                catch (err)
                {
                    callback(err);
                }
            }
        });

        const errHandler = (err) => {
            if (err) reject(ERRORS.CIPHER(err));
            else resolve();
        };

        pipeline(inputStream, cipherTransform, outputStream, errHandler);
    }
    catch (err)
    {
        reject(ERRORS.CIPHER(err));
    }
});

module.exports = cipherStream;
