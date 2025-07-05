// lek-cryptools test riguroso
const assert = require('assert');
const stream = require('stream');
const {
  getUniqueKey,
  getUniqueKeySync,
  cipher,
  cipherSync,
  decipher,
  decipherSync,
  encrypt,
  encryptSync,
  compare,
  compareSync,
  cipherStream,
  decipherStream,
  LekCryptoolsError
} = require('.');

const { Buffer } = require('buffer');

const secretKey = 'una_clave_super_segura_y_larga_32bytes!!!';
const text = 'Hola mundo, esto es un texto secreto';
const buffer = Buffer.from(text);

// SYNC CBC
(() => {
  console.log('🔐 SYNC CBC...');
  const encrypted = cipherSync(text, secretKey, 'cbc');
  console.log('  ➤ Encrypted:', encrypted.toString());
  const decrypted = decipherSync(encrypted, secretKey, 'cbc');
  console.log('  ✔ Decrypted:', decrypted);
  assert.strictEqual(decrypted, text, 'CBC sync: texto desencriptado no coincide');
})();

// SYNC GCM
(() => {
  console.log('🔐 SYNC GCM...');
  const encrypted = cipherSync(text, secretKey, 'gcm');
  console.log('  ➤ Encrypted:', encrypted.toString());
  const decrypted = decipherSync(encrypted, secretKey, 'gcm');
  console.log('  ✔ Decrypted:', decrypted);
  assert.strictEqual(decrypted, text, 'GCM sync: texto desencriptado no coincide');
})();

// SYNC CBC con Buffer
(() => {
  console.log('🔐 SYNC CBC con Buffer...');
  const encrypted = cipherSync(buffer, secretKey, 'cbc');
  console.log('  ➤ Encrypted Buffer:', encrypted.toString('hex'));
  const decrypted = decipherSync(encrypted, secretKey, 'cbc');
  console.log('  ✔ Decrypted Buffer:', decrypted.toString());
  assert(Buffer.isBuffer(decrypted), 'CBC buffer: salida no es buffer');
  assert.strictEqual(decrypted.toString(), text, 'CBC buffer: texto no coincide');
})();

// SYNC GCM con Buffer
(() => {
  console.log('🔐 SYNC GCM con Buffer...');
  const encrypted = cipherSync(buffer, secretKey, 'gcm');
  console.log('  ➤ Encrypted Buffer:', encrypted.toString('hex'));
  const decrypted = decipherSync(encrypted, secretKey, 'gcm');
  console.log('  ✔ Decrypted Buffer:', decrypted.toString());
  assert(Buffer.isBuffer(decrypted), 'GCM buffer: salida no es buffer');
  assert.strictEqual(decrypted.toString(), text, 'GCM buffer: texto no coincide');
})();

// GCM con authTag modificado (verifica integridad)
(() => {
  console.log('🧪 GCM con authTag modificado...');
  const encrypted = cipherSync(text, secretKey, 'gcm');
  const tampered = Buffer.from(encrypted);
  tampered[15] ^= 0xff; // alteramos authTag
  console.log('  ⚠️  Encrypted modificado:', tampered.toString('hex'));

  try {
      decipherSync(tampered, secretKey, 'gcm');
      assert.fail('Debe lanzar error por tag de autenticación inválido');
  } catch (err) {
      console.log('  ✔ Error capturado como se esperaba:', err.message);
      assert.ok(err instanceof Error, 'Debe lanzar Error');
  }
})();

// STREAM CBC
(() => {
  console.log('🔄 STREAM CBC...');
  const input = stream.Readable.from([text]);
  const encryptedChunks = [];
  const encryptedStream = new stream.PassThrough();
  encryptedStream.on('data', chunk => encryptedChunks.push(chunk));
  encryptedStream.on('end', () => {
    const encrypted = Buffer.concat(encryptedChunks);
    const decInput = stream.Readable.from([encrypted]);
    const decryptedChunks = [];
    const decryptedStream = new stream.PassThrough();
    decryptedStream.on('data', chunk => decryptedChunks.push(chunk));
    decryptedStream.on('end', () => {
      const decrypted = Buffer.concat(decryptedChunks).toString();
      console.log('  ✔ Decrypted STREAM CBC:', decrypted);
      assert.strictEqual(decrypted, text, 'STREAM CBC: texto desencriptado no coincide');
    });
    decipherStream(decInput, decryptedStream, secretKey, 'cbc');
  });
  cipherStream(input, encryptedStream, secretKey, 'cbc');
})();

// STREAM GCM
(() => {
  console.log('🔄 STREAM GCM...');
  const input = stream.Readable.from([text]);
  const encryptedChunks = [];
  const encryptedStream = new stream.PassThrough();
  encryptedStream.on('data', chunk => encryptedChunks.push(chunk));
  encryptedStream.on('end', () => {
    const encrypted = Buffer.concat(encryptedChunks);
    const decInput = stream.Readable.from([encrypted]);
    const decryptedChunks = [];
    const decryptedStream = new stream.PassThrough();
    decryptedStream.on('data', chunk => decryptedChunks.push(chunk));
    decryptedStream.on('end', () => {
      const decrypted = Buffer.concat(decryptedChunks).toString();
      console.log('  ✔ Decrypted STREAM GCM:', decrypted);
      assert.strictEqual(decrypted, text, 'STREAM GCM: texto desencriptado no coincide');
    });
    decipherStream(decInput, decryptedStream, secretKey, 'gcm');
  });
  cipherStream(input, encryptedStream, secretKey, 'gcm');
})();
