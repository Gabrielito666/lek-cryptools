const { createDecipheriv } = require('crypto');
const { decipherChunk, getKeyFromSecret } = require('../tools');

const { pipeline, Transform } = require('stream');
const ERRORS = require('../errors'); 
const decipherStream = (inputStream, outputStream, secretKey) => new Promise((resolve, reject) =>
{
    try
    {
        const STATES =
        {
            iv : "",
            ivIsReconstructed : false,
            decipher_ : undefined
        }
        const key = getKeyFromSecret(secretKey);

        const decipherTransform = new Transform(
        {
            transform(chunk, encoding, callback)
            {
                if(chunk.includes(":") && !STATES.ivIsReconstructed)
                {
                    STATES.ivIsReconstructed = true;
                    const [ivFinal, firstData] = chunk.toString().split(":");
                    STATES.iv = Buffer.from(STATES.iv + ivFinal, 'hex');
                    STATES.decipher_ = createDecipheriv('aes-256-cbc', key, STATES.iv);

                    const deciphredChunk = decipherChunk(firstData, STATES.decipher_);
                    callback(null, deciphredChunk);
                }
                else if(!STATES.ivIsReconstructed)
                {
                    STATES.iv += chunk.toString();
                    callback();
                }
                else
                {
                    const deciphredChunk = decipherChunk(chunk, STATES.decipher_);
                    callback(deciphredChunk);
                }
            }
        })
        
        pipeline(
            inputStream,
            decipherTransform,
            outputStream,
            (err) => {
                if (err)
                {
                    reject(ERRORS.DECIPHER);
                }
                else
                {
                    resolve()
                }
            }
        );
    } catch (err)
    {
        reject(ERRORS.DECIPHER);
    }
});

module.exports = decipherStream;