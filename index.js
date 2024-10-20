const { getUniqueKey } = require('./lib/tools');
const cipher = require('./lib/cipher');
const decipher = require('./lib/decipher');
const encrypt = require('./lib/encrypt');
const { compare } = require('bcryptjs');
const cipherStream = require('./lib/cipherStream');
const decipherStream = require('./lib/decipherStream');

module.exports = { getUniqueKey, cipher, decipher, encrypt, compare, cipherStream, decipherStream };