// MyPass — encryption helpers (Web Crypto API).
//
// The master password is never stored. It is stretched into an AES-256 key
// with PBKDF2-SHA256 and a random salt, and the vault is encrypted with
// AES-GCM using a fresh random IV on every save. What gets stored is only:
//   { version, kdf, iterations, salt, iv, data }   (all binary parts in Base64)

const VERSION = 1;
const KDF = "PBKDF2-SHA256";
const ITERATIONS = 600_000;
const MIN_ITERATIONS = 100_000; // refuse blobs that ask for suspiciously cheap/expensive work
const MAX_ITERATIONS = 5_000_000;
const SALT_BYTES = 16;
const IV_BYTES = 12;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function base64ToBytes(text) {
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function deriveKey(password, salt, iterations) {
  const material = await crypto.subtle.importKey(
    "raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false, // the key can never be exported from the browser
    ["encrypt", "decrypt"],
  );
}

/** Start a new session for a new vault: random salt + key derived from the password. */
export async function createSession(password) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const key = await deriveKey(password, salt, ITERATIONS);
  return { key, salt, iterations: ITERATIONS };
}

/** Encrypt text with an open session. Returns the object that is stored. */
export async function encryptVault(plaintext, session) {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, session.key, encoder.encode(plaintext),
  );
  return {
    version: VERSION,
    kdf: KDF,
    iterations: session.iterations,
    salt: bytesToBase64(session.salt),
    iv: bytesToBase64(iv),
    data: bytesToBase64(new Uint8Array(encrypted)),
  };
}

/** Quick shape check, used to tell an encrypted backup from a plain data.json. */
export function isEncryptedBlob(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    value.version === VERSION &&
    value.kdf === KDF &&
    Number.isInteger(value.iterations) &&
    typeof value.salt === "string" &&
    typeof value.iv === "string" &&
    typeof value.data === "string"
  );
}

/** Decrypt a stored blob. Returns { plaintext, session }; throws on a wrong password. */
export async function decryptVault(blob, password) {
  if (!isEncryptedBlob(blob)) throw new Error("This is not a MyPass encrypted file.");
  if (blob.iterations < MIN_ITERATIONS || blob.iterations > MAX_ITERATIONS) {
    throw new Error("This file has unsupported encryption settings.");
  }

  let salt, iv, data;
  try {
    salt = base64ToBytes(blob.salt);
    iv = base64ToBytes(blob.iv);
    data = base64ToBytes(blob.data);
  } catch {
    throw new Error("The encrypted data is damaged.");
  }

  const key = await deriveKey(password, salt, blob.iterations);
  try {
    const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
    return {
      plaintext: decoder.decode(decrypted),
      session: { key, salt, iterations: blob.iterations },
    };
  } catch {
    // AES-GCM authentication fails for a wrong password and for tampered data alike.
    throw new Error("Wrong master password, or the data is damaged.");
  }
}
