/**
 * @typedef {import("../../lib/types/index").LekCryptoolsErrorClass} LekCryptoolsErrorClass
 * @typedef {import("../../lib/types/index").LekCryptoolsErrorType} LekCryptoolsErrorType
 */
/**
 * @class
 * @implements {LekCryptoolsErrorType}
 * @type {LekCryptoolsErrorClass}
 */
class LekCryptoolsError extends Error
{
    constructor(msg, err) { super('Error in lek-cryptools ' + msg + ": " + err.message) }
}
const ERRORS =
{
    CIPHER: (err) => new LekCryptoolsError('when trying to cipher the key', err),
    DECIPHER: (err) => new LekCryptoolsError('when trying to decipher the key', err),
    LekCryptoolsError
}
module.exports = ERRORS;