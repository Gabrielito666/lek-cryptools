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

const TEST_SECRET = 'test-secret';
const TEST_STRING = 'hola mundo';
const TEST_BUFFER = Buffer.from(TEST_STRING, 'utf-8');

(async () => {
  console.log('🔑 Testing getUniqueKey / getUniqueKeySync...');
  const key1 = getUniqueKeySync(32);
  const key2 = await getUniqueKey(32);
  assert.strictEqual(typeof key1, 'string');
  assert.strictEqual(typeof key2, 'string');
  assert.strictEqual(key1.length, 64);
  assert.strictEqual(key2.length, 64);

  console.log('🔐 Testing encrypt / encryptSync + compare / compareSync...');
  const hashSync = encryptSync(TEST_STRING);
  const hashAsync = await encrypt(TEST_STRING);
  assert.ok(compareSync(TEST_STRING, hashSync));
  assert.ok(await compare(TEST_STRING, hashAsync));

  console.log('🔒 Testing cipherSync / decipherSync with string...');
  const cipheredStr = cipherSync(TEST_STRING, TEST_SECRET);
  const decipheredStr = decipherSync(cipheredStr, TEST_SECRET);
  assert.strictEqual(decipheredStr, TEST_STRING);

  console.log('🔒 Testing cipherSync / decipherSync with Buffer...');
  const cipheredBuf = cipherSync(TEST_BUFFER, TEST_SECRET);
  const decipheredBuf = decipherSync(cipheredBuf, TEST_SECRET);
  assert.ok(Buffer.isBuffer(decipheredBuf));
  assert.strictEqual(decipheredBuf.toString(), TEST_STRING);

  console.log('🔒 Testing cipher / decipher (async) with string...');
  const cipheredStrAsync = await cipher(TEST_STRING, TEST_SECRET);
  const decipheredStrAsync = await decipher(cipheredStrAsync, TEST_SECRET);
  assert.strictEqual(decipheredStrAsync, TEST_STRING);

  console.log('🔒 Testing cipher / decipher (async) with Buffer...');
  const cipheredBufAsync = await cipher(TEST_BUFFER, TEST_SECRET);
  const decipheredBufAsync = await decipher(cipheredBufAsync, TEST_SECRET);
  assert.ok(Buffer.isBuffer(decipheredBufAsync));
  assert.strictEqual(decipheredBufAsync.toString(), TEST_STRING);

  console.log('📤 Testing cipherStream / decipherStream...');
  const input1 = new stream.Readable({
    read() {
      this.push(TEST_BUFFER);
      this.push(null);
    }
  });
  const encryptedChunks = [];
  const encryptedStream = new stream.Writable({
    write(chunk, enc, cb) {
      encryptedChunks.push(chunk);
      cb();
    }
  });

  await cipherStream(input1, encryptedStream, TEST_SECRET);
  const encryptedResult = Buffer.concat(encryptedChunks);

  const input2 = new stream.Readable({
    read() {
      this.push(encryptedResult);
      this.push(null);
    }
  });
  const decryptedChunks = [];
  const decryptedStream = new stream.Writable({
    write(chunk, enc, cb) {
      decryptedChunks.push(chunk);
      cb();
    }
  });

  await decipherStream(input2, decryptedStream, TEST_SECRET);
  const decryptedResult = Buffer.concat(decryptedChunks).toString();
  assert.strictEqual(decryptedResult, TEST_STRING);

  console.log('✅ All tests passed!');
})().catch(err => {
  console.error('❌ Test failed:');
  if (err instanceof LekCryptoolsError) {
    console.error('LekCryptoolsError:', err.message);
  } else {
    console.error(err);
  }
  process.exit(1);
});