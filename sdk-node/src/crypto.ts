import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign as nodeSign,
  timingSafeEqual,
  verify as nodeVerify,
} from "node:crypto";
import { Buffer } from "node:buffer";
import { fromBase64, toBuffer, type DataLike } from "./encoding.js";

export interface SymmetricKey {
  key: string | Uint8Array;
  keyId?: string;
  keyVersion?: number;
}

export type SymmetricKeyInput = SymmetricKey | string | Uint8Array;

export interface EncryptedPayload {
  algorithm: "AES-256-GCM";
  keyId?: string;
  keyVersion?: number;
  nonce: string;
  ciphertext: string;
  authTag: string;
  associatedData?: string;
}

export interface SignOptions {
  privateKeyPem?: string;
  keyId?: string;
}

export interface VerifyOptions {
  publicKeyPem?: string;
}

export interface SignatureResult {
  algorithm: "Ed25519";
  signature: string;
  keyId?: string;
  publicKeySha256?: string;
}

export function resolveSymmetricKey(key: SymmetricKeyInput): { rawKey: Buffer; keyId?: string; keyVersion?: number } {
  if (typeof key === "string") {
    const b64 = fromBase64(key);
    if (b64.length === 32) {
      return { rawKey: b64 };
    }
    const utf8Buf = Buffer.from(key, "utf8");
    if (utf8Buf.length === 32) {
      return { rawKey: utf8Buf };
    }
    throw new Error(`AES-256-GCM key must be 32 bytes, got ${b64.length} bytes`);
  }

  if (key instanceof Uint8Array || Buffer.isBuffer(key)) {
    const buf = Buffer.from(key);
    if (buf.length !== 32) {
      throw new Error(`AES-256-GCM key must be 32 bytes, got ${buf.length} bytes`);
    }
    return { rawKey: buf };
  }

  if (typeof key === "object" && key !== null && "key" in key) {
    const rawKey = fromBase64(key.key);
    if (rawKey.length !== 32) {
      throw new Error(`AES-256-GCM key must be 32 bytes, got ${rawKey.length} bytes`);
    }
    return { rawKey, keyId: key.keyId, keyVersion: key.keyVersion };
  }

  throw new Error("Invalid symmetric key format");
}

export function sha256(input: DataLike): string {
  return createHash("sha256").update(toBuffer(input)).digest("base64");
}

export function hmacSha256(input: DataLike, key: string | Uint8Array): string {
  return createHmac("sha256", fromBase64(key)).update(toBuffer(input)).digest("base64");
}

export function verifyHmacSha256(input: DataLike, expectedBase64: string, key: string | Uint8Array): boolean {
  const actual = Buffer.from(hmacSha256(input, key), "base64");
  const expected = Buffer.from(expectedBase64, "base64");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export function encryptAes256Gcm(input: DataLike, key: SymmetricKeyInput, associatedData?: DataLike): EncryptedPayload {
  const { rawKey, keyId, keyVersion } = resolveSymmetricKey(key);

  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", rawKey, nonce);
  const aad = associatedData === undefined ? undefined : toBuffer(associatedData);
  if (aad) {
    cipher.setAAD(aad);
  }

  const ciphertext = Buffer.concat([cipher.update(toBuffer(input)), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    algorithm: "AES-256-GCM",
    keyId,
    keyVersion,
    nonce: nonce.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    authTag: authTag.toString("base64"),
    associatedData: aad?.toString("base64"),
  };
}

export function decryptAes256Gcm(payload: EncryptedPayload, key: SymmetricKeyInput): Buffer {
  const { rawKey } = resolveSymmetricKey(key);

  const decipher = createDecipheriv("aes-256-gcm", rawKey, Buffer.from(payload.nonce, "base64"));
  if (payload.associatedData) {
    decipher.setAAD(Buffer.from(payload.associatedData, "base64"));
  }
  decipher.setAuthTag(Buffer.from(payload.authTag, "base64"));

  return Buffer.concat([decipher.update(Buffer.from(payload.ciphertext, "base64")), decipher.final()]);
}

export function signEd25519(input: DataLike, options: SignOptions | string): SignatureResult {
  const privateKeyPem = typeof options === "string" ? options : options.privateKeyPem;
  const keyId = typeof options === "string" ? undefined : options.keyId;

  if (!privateKeyPem) {
    throw new Error("privateKeyPem is required for Ed25519 signing");
  }

  const privateKey = createPrivateKey(privateKeyPem);
  const signature = nodeSign(null, toBuffer(input), privateKey).toString("base64");
  const publicKeyPem = createPublicKey(privateKey).export({ type: "spki", format: "pem" }).toString();

  return {
    algorithm: "Ed25519",
    signature,
    keyId,
    publicKeySha256: sha256(publicKeyPem),
  };
}

export function verifyEd25519(input: DataLike, signatureBase64: string, options: VerifyOptions | string): boolean {
  const publicKeyPem = typeof options === "string" ? options : options.publicKeyPem;

  if (!publicKeyPem) {
    throw new Error("publicKeyPem is required for Ed25519 verification");
  }

  return nodeVerify(null, toBuffer(input), createPublicKey(publicKeyPem), Buffer.from(signatureBase64, "base64"));
}
