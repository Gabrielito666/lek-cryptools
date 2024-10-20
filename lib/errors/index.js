const ERRORS =
{
    CIPHER: new Error('error in lek-cryptools when trying to encrypt the key: ' + err.message),
    DECIPHER: new Error('error in lek-cryptools when trying to decipher the key: ' + err.message),

}
module.exports = ERRORS;