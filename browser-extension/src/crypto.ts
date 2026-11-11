const DB_NAME = "securelayer-extension";
const STORE_NAME = "keys";
const DEVICE_KEY_ID = "device-signing-key";

let memoryKeyPair: CryptoKeyPair | undefined;

/**
 * Computes the SHA-256 digest of an input string or byte array, returning base64.
 */
export async function sha256Base64(input: string | Uint8Array): Promise<string> {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : new Uint8Array(input);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return bytesToBase64(new Uint8Array(digest));
}

/**
 * Generates or retrieves the device signing key pair using the Web Crypto API.
 * The private key is strictly generated with extractable=false and stored in
 * the extension's isolated IndexedDB store, preventing leakage to webpage scripts.
 */
export async function ensureDeviceKey(): Promise<CryptoKeyPair> {
  const existing = await readKeyPair();
  if (existing) {
    return existing;
  }

  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false, // extractable: false — private key cannot be exported or leaked
    ["sign", "verify"],
  );
  await writeKeyPair(keyPair);
  return keyPair;
}

/**
 * Computes a deterministic SHA-256 thumbprint for the public key.
 */
export async function publicJwkThumbprint(keyPair: CryptoKeyPair): Promise<string> {
  const exported = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  return sha256Base64(JSON.stringify({
    crv: exported.crv,
    kty: exported.kty,
    x: exported.x,
    y: exported.y,
  }));
}

/**
 * Exports the public key as a JWK for proof-of-possession registration.
 */
export async function publicJwk(keyPair: CryptoKeyPair): Promise<JsonWebKey> {
  return crypto.subtle.exportKey("jwk", keyPair.publicKey);
}

/**
 * Digitally signs a structured payload using ECDSA P-256 SHA-256.
 */
export async function signContext(payload: unknown, keyPair: CryptoKeyPair): Promise<string> {
  const bytes = new TextEncoder().encode(JSON.stringify(payload));
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keyPair.privateKey, bytes);
  return bytesToBase64(new Uint8Array(signature));
}

/**
 * Verifies an ECDSA P-256 signature using the public key.
 */
export async function verifySignature(payload: unknown, signatureBase64: string, publicKey: CryptoKey): Promise<boolean> {
  const bytes = new TextEncoder().encode(JSON.stringify(payload));
  const signatureBytes = base64ToBytes(signatureBase64);
  return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, signatureBytes as unknown as BufferSource, bytes);
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

export function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function resetKeyForTesting(): void {
  memoryKeyPair = undefined;
}

async function readKeyPair(): Promise<CryptoKeyPair | undefined> {
  if (typeof indexedDB === "undefined") {
    return memoryKeyPair;
  }
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const request = db.transaction(STORE_NAME).objectStore(STORE_NAME).get(DEVICE_KEY_ID);
    request.onsuccess = () => resolve(request.result as CryptoKeyPair | undefined);
    request.onerror = () => reject(request.error);
  });
}

async function writeKeyPair(keyPair: CryptoKeyPair): Promise<void> {
  if (typeof indexedDB === "undefined") {
    memoryKeyPair = keyPair;
    return;
  }
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const request = db.transaction(STORE_NAME, "readwrite").objectStore(STORE_NAME).put(keyPair, DEVICE_KEY_ID);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => {
      request.result.createObjectStore(STORE_NAME);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}
