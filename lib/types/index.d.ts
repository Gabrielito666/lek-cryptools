import { Readable, Writable } from 'stream';
//TOOLS
/**
 * with this function a key to the secret is obtained.
 */
export type GetKeyFromSecretFunction = (secretKey: string) => Buffer;

/**
 * Generates a random 16-byte initialization vector (IV).
 */
export type GetIVFunction = () => Buffer;

/**
 * get a unique key
 */
export type GetUniqueKeySyncFunction = (num?: number) => string;

/**
 * get a unique key
 */
export type GetUniqueKeyFunction = (num?: number) => Promise<string>;

//CIPHER

/**
 * sync function to encrypt a string or buffer
 */
export type CipherSyncFunction = <T extends string | Buffer>(
  data: T,
  secretKey: string
) => T;
  
/**
 * async function to encrypt a string or buffer
 */
export type CipherFunction = <T extends string | Buffer>(
data: T,
secretKey: string
) => Promise<T>;

//DECIPHER

/**
 * sync function to decrypt a string or buffer
 */
export type DecipherSyncFunction = <T extends string | Buffer>(
    encrypted: T,
    secretKey: string
) => T;

/**
 * async function to decrypt a string or buffer
 */
export type DecipherFunction = <T extends string | Buffer>(
encrypted: T,
secretKey: string
) => Promise<T>;

//ENCRYPT
/**
 * async encrypt a key
 */
export type EncryptFunction = (
  data: string,
  num?: number
) => Promise<string>;

/**
 * sync encrypt a key
 */
export type EncryptSyncFunction = (
  data: string,
  num?: number
) => string;

//CIPHER STREAM

/**
 * encrypt a readable stream and write to output stream
 */
export type CipherStreamFunction = (
  inputStream: Readable,
  outputStream: Writable,
  secretKey: string
) => Promise<void>;


//DECIPHER STREAM

/**
 * decrypt a readable stream and write to output stream
 */
export type DecipherStreamFunction = (
  inputStream: Readable,
  outputStream: Writable,
  secretKey: string
) => Promise<void>;

export interface LekCryptoolsAPI {
  getUniqueKey: GetUniqueKeyFunction;
  getUniqueKeySync: GetUniqueKeySyncFunction;
  cipher: CipherFunction;
  cipherSync: CipherSyncFunction;
  decipher: DecipherFunction;
  decipherSync: DecipherSyncFunction;
  encrypt: EncryptFunction;
  encryptSync: EncryptSyncFunction;
  compare: (data: string, encrypted: string) => Promise<boolean>;
  compareSync: (data: string, encrypted: string) => boolean;
  cipherStream: CipherStreamFunction;
  decipherStream: DecipherStreamFunction;
  LekCryptoolsError: typeof import("../errors/index");
}