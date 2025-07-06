import { Readable, Writable } from 'stream';
//TOOLS
/**
 * with this function a key to the secret is obtained.
 */
export type GetKeyFromSecretFunction = (secretKey: string) => Buffer;

/**
 * Generates a random 16 or 12 -byte initialization vector (IV).
 */
export type GetIVFunction = (mode:"cbc"|"gcm") => Buffer;

/**
 * get a unique key
 */
export type GetUniqueKeySyncFunction = (num?: number) => string;

/**
 * get a unique key
 */
export type GetUniqueKeyFunction = (num?: number) => Promise<string>;

/**
 * is or not an hexagecimal string
 */
export type IsHexFunction = (str:string) => boolean;
//CIPHER

/**
 * sync function to encrypt a string or buffer
 */
export type CipherSyncFunction = <T extends string | Buffer>(
  data: T,
  secretKey: string,
  mode?:"cbc"|"gcm"
) => T;
  
/**
 * async function to encrypt a string or buffer
 */
export type CipherFunction = <T extends string | Buffer>(
data: T,
secretKey: string,
mode?:"cbc"|"gcm"
) => Promise<T>;

//DECIPHER

/**
 * sync function to decrypt a string or buffer
 */
export type DecipherSyncFunction = <T extends string | Buffer>(
  encrypted: T,
  secretKey: string,
  mode?: "cbc"|"gcm"
) => T;

/**
 * async function to decrypt a string or buffer
 */
export type DecipherFunction = <T extends string | Buffer>(
  encrypted: T,
  secretKey: string,
  mode?: "cbc"|"gcm"
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
  secretKey: string,
  mode?: "cbc"|"gcm"
) => Promise<void>;


//DECIPHER STREAM

/**
 * decrypt a readable stream and write to output stream
 */
export type DecipherStreamFunction = (
  inputStream: Readable,
  outputStream: Writable,
  secretKey: string,
  mode?: "cbc"|"gcm"
) => Promise<void>;

//ERRORS
export interface LekCryptoolsErrorType extends Error{};
export interface LekCryptoolsErrorClass extends Function{
  new(msg:string, err:Error):LekCryptoolsErrorType;
  prototype: Error;
}

export interface LekCryptoolsAPI {
  getUniqueKey(num?: number): Promise<string>;
  getUniqueKeySync(num?: number): string;
  cipher<T extends string | Buffer>(data: T, secretKey: string, mode?:"cbc"|"gcm"): Promise<T>;
  cipherSync<T extends string | Buffer>(data: T, secretKey: string, mode?:"cbc"|"gcm"): T;
  decipher<T extends string | Buffer>(data: T, secretKey: string, mode?:"cbc"|"gcm"): Promise<T>;
  decipherSync<T extends string | Buffer>(data: T, secretKey: string, mode?:"cbc"|"gcm"): T;
  encrypt(data: string, num?: number): Promise<string>;
  encryptSync(data: string, num?: number): string;
  compare(data: string, encrypted: string): Promise<boolean>;
  compareSync(data: string, encrypted: string): boolean;
  cipherStream(input: Readable, output: Writable, key: string, mode?:"cbc"|"gcm"): Promise<void>;
  decipherStream(input: Readable, output: Writable, key: string, mode?:"cbc"|"gcm"): Promise<void>;
  LekCryptoolsError: LekCryptoolsErrorClass;
}