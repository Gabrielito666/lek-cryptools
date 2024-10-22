const { createCipheriv } = require('crypto');
const { getIV, getKeyFromSecret } = require('../tools');
const { Transform, pipeline } = require('stream');
const ERRORS = require('../errors')

const cipherStream = (inputStream, outputStream, secretKey) => new Promise((resolve, reject) =>
{
    try
    {
        const key = getKeyFromSecret(secretKey);
        if(key.length !== 32) throw new Error('Invalid key. system need a 32 bits key');

        const iv = getIV();

        outputStream.write(iv);
        const cipher_ = createCipheriv('aes-256-cbc', key, iv);

        const cipherTransform = new Transform
        ({
            transform(chunk, encoding, callback)
            {
                const ciphred = cipher_.update(chunk);
                callback(null, ciphred);
            },
            flush(callback)
            {
                try         { callback(null, cipher_.final()) }
                catch (err) { callback(err) }
            }
        });

        const errHandler = (err) =>
        {
            if (err)    reject(ERRORS.CIPHER(err));
            else        resolve();
        }
        pipeline(inputStream, cipherTransform, outputStream, errHandler);
    }
    catch (err) { reject(ERRORS.CIPHER(err)) }
});

module.exports = cipherStream;