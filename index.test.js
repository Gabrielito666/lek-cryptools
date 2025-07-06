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

const getUniqueKeyProof = async() =>
{
  console.log(getUniqueKeySync());
  console.log(await getUniqueKey());
}

/**
 * 
 * @param {"sync"|"async"} syncOrAsync 
 * @param {"buffer"|"string"} bufferOrString 
 * @param {"cbc"|"gcm"} method
 * @param {string} original 
 * @param {string} secretKey 
 * @returns {function}
 */
const getCipherDacipherTests = (syncOrAsync, bufferOrString, method, original, secretKey) => async() =>
{

  const testName = `TEST ${syncOrAsync}-${bufferOrString}`;

  const cipherFunction = syncOrAsync === "async" ? cipher : cipherSync;
  const decipherFunction = syncOrAsync === "async" ? decipher : decipherSync;

  const originalData = bufferOrString === "string" ? original : Buffer.from(original);

  const ciphred = await cipherFunction(originalData, secretKey, method);
  const deciphred = await decipherFunction(ciphred, secretKey, method);

  const deciphredData = bufferOrString === "string" ? deciphred : deciphred.toString();

  //console.log(original);
  //console.log(ciphred);
  //console.log(deciphredData);

  if(original === deciphredData && original !== ciphred)
  {
    console.log(testName, "APROVED");
  }
  else
  {
    console.error(testName, "REJECTED");
  }
}

/**
 * Prueba que el modo GCM detecta claves alteradas.
 * 
 * @param {"sync"|"async"} syncOrAsync 
 * @param {"buffer"|"string"} bufferOrString 
 * @param {string} original 
 * @param {string} secretKey 
 * @returns {function}
 */
const getGcmIntegrityTest = (syncOrAsync, bufferOrString, original, secretKey) => async () =>
{
  const testName = `INTEGRITY GCM ${syncOrAsync}-${bufferOrString}`;

  const cipherFunction = syncOrAsync === "async" ? cipher : cipherSync;
  const decipherFunction = syncOrAsync === "async" ? decipher : decipherSync;

  const originalData = bufferOrString === "string" ? original : Buffer.from(original);

  try {
    const ciphred = await cipherFunction(originalData, secretKey, "gcm");

    // Alteramos la clave levemente (agregamos un carácter)
    const corruptedCiphred = bufferOrString === "string" ?
      ciphred + "trash-bytes" :
      Buffer.concat([ciphred, Buffer.from("trash-bytes")])
    ;

    await decipherFunction(corruptedCiphred, secretKey, "gcm");

    // Si NO lanza error, la prueba falla
    console.error(testName, "REJECTED (no se detectó alteración)");
  } catch (err) {
    // Si lanza error, se aprueba (como debe ser en GCM)
    console.log(testName, "APROVED (error capturado)");
  }
}

/**
 * Prueba que descifrar con clave incorrecta lanza error (como debe ser).
 * 
 * @param {"sync"|"async"} syncOrAsync 
 * @param {"buffer"|"string"} bufferOrString 
 * @param {"cbc"|"gcm"} method
 * @param {string} original 
 * @param {string} secretKey 
 * @returns {function}
 */
const getWrongKeyTest = (syncOrAsync, bufferOrString, method, original, secretKey) => async () =>
{
  const testName = `WRONG KEY ${syncOrAsync}-${bufferOrString}-${method}`;

  const cipherFunction = syncOrAsync === "async" ? cipher : cipherSync;
  const decipherFunction = syncOrAsync === "async" ? decipher : decipherSync;

  const originalData = bufferOrString === "string" ? original : Buffer.from(original);

  try {
    const ciphred = await cipherFunction(originalData, secretKey, method);

    // Usamos clave incorrecta para descifrar
    const wrongKey = secretKey + "_bad";

    await decipherFunction(ciphred, wrongKey, method);

    // Si no lanza error, el test falla
    console.error(testName, "REJECTED (no se detectó clave incorrecta)");
  } catch (err) {
    // Si lanza error, el test pasa
    console.log(testName, "APROVED (error capturado)");
  }
}


const runTests = async(...tests) =>
{
  for(let test of tests)
  {
    await test();
  }
}

const original = "this is a text to proof encription";
const secretKey = "this-is-a-secret-key";

const largeOriginal = "576bd8bd6be4c6fb9122be73da55277a8b77495bc2d999396e551846c48bba54a698a47ca336fa8b51c3a2e62b98bb7cf9123a3303b1fb180d97666123e27d6861b20aa3f3ab5158b9ceb7cab7590b022c8c1901530290896aeb1461907b64f8";

const tests = [
  getCipherDacipherTests("sync", "string", "cbc", original, secretKey),
  getCipherDacipherTests("async", "string", "cbc", original, secretKey),
  getCipherDacipherTests("sync", "buffer", "cbc", original, secretKey),
  getCipherDacipherTests("async", "buffer", "cbc", original, secretKey),
  getCipherDacipherTests("sync", "string", "gcm", original, secretKey),
  getCipherDacipherTests("async", "string", "gcm", original, secretKey),
  getCipherDacipherTests("sync", "buffer", "gcm", original, secretKey),
  getCipherDacipherTests("async", "buffer", "gcm", original, secretKey),

  getGcmIntegrityTest("sync", "string", original, secretKey),
  getGcmIntegrityTest("async", "string", original, secretKey),
  getGcmIntegrityTest("sync", "buffer", original, secretKey),
  getGcmIntegrityTest("async", "buffer", original, secretKey),

  getGcmIntegrityTest("sync", "string", largeOriginal, secretKey),
  getGcmIntegrityTest("async", "string", largeOriginal, secretKey),
  getGcmIntegrityTest("sync", "buffer", largeOriginal, secretKey),
  getGcmIntegrityTest("async", "buffer", largeOriginal, secretKey),

  getWrongKeyTest("sync", "string", "cbc", original, secretKey),
  getWrongKeyTest("async", "string", "cbc", original, secretKey),
  getWrongKeyTest("sync", "buffer", "cbc", original, secretKey),
  getWrongKeyTest("async", "buffer", "cbc", original, secretKey),
  getWrongKeyTest("sync", "string", "gcm", original, secretKey),
  getWrongKeyTest("async", "string", "gcm", original, secretKey),
  getWrongKeyTest("sync", "buffer", "gcm", original, secretKey),
  getWrongKeyTest("async", "buffer", "gcm", original, secretKey),
]

runTests(...tests);