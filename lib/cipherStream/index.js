const { createCipheriv } = require('crypto');
const { getIV, getKeyFromSecret, cipherChunk } = require('../tools');
const { Transform, pipeline } = require('stream');

const cipherStream = (inputStream, outputStream, secretKey) => new Promise((resolve, reject) =>
{
    try
    {
        const key = getKeyFromSecret(secretKey);
        const iv = getIV();

        outputStream.write(iv.toString('hex') + ':');

        const cipher_ = createCipheriv('aes-256-cbc', key, iv);

        const cipherTransform = new Transform
        ({
            transform(chunk, encoding, callback)
            {
                const ciphredChunk = cipherChunk(chunk, cipher_)
                callback(null, ciphredChunk);
            }
        });

        pipeline(
            inputStream,
            cipherTransform,
            outputStream,
            (err) =>
            {
                if (err)
                {
                    reject(new Error('Error en lek-cryptools cuando se intentaba cifrar el stream: ' + err.message));
                }
                else
                {
                    resolve();
                }
            }
        );
    }
    catch (err)
    {
        reject(new Error('Error en lek-cryptools cuando se intentaba cifrar la clave: ' + err.message));
    }
});

module.exports = cipherStream;