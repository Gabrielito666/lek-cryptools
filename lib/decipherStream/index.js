const { createDecipheriv } = require('crypto');
const { getKeyFromSecret } = require('../tools');
const { pipeline, Transform } = require('stream');
const ERRORS = require('../errors');

/**
 * @typedef {import("../../lib/types/index").DecipherStreamFunction} DecipherStreamFunction
 */

/** @type {DecipherStreamFunction} */
const decipherStream = (inputStream, outputStream, secretKey) => new Promise((resolve, reject) =>
{
    try
    {
        const STATES = {
            iv: Buffer.alloc(0),
            ivIsReconstructed: false,
            decipher_: undefined
        };

        const key = getKeyFromSecret(secretKey);
        if (key.length !== 32) throw new Error('Invalid key. System needs a 32-byte key');

        const decipherTransform = new Transform({
            transform(chunk, encoding, callback) {
                if (!STATES.ivIsReconstructed) {
                    const bitsRest = 16 - STATES.iv.length;
                    if (chunk.length > bitsRest) {
                        STATES.ivIsReconstructed = true;
                        const rest = chunk.slice(0, bitsRest);
                        const firstData = chunk.slice(bitsRest);
                        STATES.iv = Buffer.concat([STATES.iv, rest]);
                        STATES.decipher_ = createDecipheriv('aes-256-cbc', key, STATES.iv);

                        const deciphred = STATES.decipher_.update(firstData);
                        callback(null, deciphred);
                    } else {
                        STATES.iv = Buffer.concat([STATES.iv, chunk]);
                        callback();
                    }
                } else {
                    const deciphred = STATES.decipher_.update(chunk);
                    callback(null, deciphred);
                }
            },
            flush(callback) {
                try {
                    callback(null, STATES.decipher_.final());
                } catch (err) {
                    callback(err);
                }
            }
        });

        const errHandler = (err) => {
            if (err) reject(ERRORS.DECIPHER(err));
            else resolve();
        };

        pipeline(inputStream, decipherTransform, outputStream, errHandler);
    }
    catch (err) {
        reject(ERRORS.DECIPHER(err));
    }
});

module.exports = decipherStream;
