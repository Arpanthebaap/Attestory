// Attestory Cryptographic Engine
//
// Zero-Knowledge Primitives running natively in the client via Web Crypto API:
//   - AES-256-GCM authenticated encryption for all journal entries
//   - PBKDF2 key derivation (150,000 iterations, SHA-256)
//   - Cryptographic SHA-256 blockchain-style hash chaining
//   - Zero-Knowledge Key Wrapping (AES-KW / AES-GCM) for Emergency Recovery Kits
//   - Live tamper detection & mathematical proof generation

const enc = new TextEncoder();
const dec = new TextDecoder();

export function toB64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

export function fromB64(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)).buffer;
}

export function randomSaltB64() {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return toB64(salt);
}

// Derive an AES-GCM key from passphrase + per-user salt using PBKDF2 (150,000 rounds)
export async function deriveKey(passphrase, saltB64) {
  const baseKey = await crypto.subtle.importKey(
    'raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: fromB64(saltB64), iterations: 150000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    true, // extractable for Recovery Kit wrapping
    ['encrypt', 'decrypt']
  );
}

export async function encryptText(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, key, enc.encode(plaintext)
  );
  return { ciphertext: toB64(ciphertext), iv: toB64(iv) };
}

export async function decryptText(key, ciphertextB64, ivB64) {
  const plaintextBuf = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromB64(ivB64) }, key, fromB64(ciphertextB64)
  );
  return dec.decode(plaintextBuf);
}

// --- Integrity Ledger & Hash Chaining ---
// Entry Hash = SHA-256(prevHash + "|" + ciphertext + "|" + iv)
export async function sha256Hex(str) {
  const hashBuf = await crypto.subtle.digest('SHA-256', enc.encode(str));
  return Array.from(new Uint8Array(hashBuf)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function computeEntryHash(previousHash, ciphertextB64, ivB64) {
  return sha256Hex(`${previousHash}|${ciphertextB64}|${ivB64}`);
}

export const GENESIS_HASH = '0'.repeat(64);

// Verifies a full ordered list of entries [{ciphertext, iv, prevHash, hash}, ...].
// Returns detailed verification status, chain node diagnostics, and tamper indicators.
export async function verifyChain(entries) {
  let expectedPrev = GENESIS_HASH;
  const nodes = [];

  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    const prevMatches = (e.prevHash === expectedPrev);
    const recomputed = await computeEntryHash(e.prevHash, e.ciphertext, e.iv);
    const hashMatches = (recomputed === e.hash);

    const isBlockValid = prevMatches && hashMatches;

    nodes.push({
      index: i + 1,
      hash: e.hash,
      shortHash: e.hash ? `${e.hash.substring(0, 8)}...${e.hash.substring(56)}` : '???',
      prevHash: e.prevHash,
      shortPrev: e.prevHash ? `${e.prevHash.substring(0, 8)}...` : '00000000...',
      isValid: isBlockValid,
      reason: !prevMatches ? 'Chain link broken (prevHash mismatch)' : (!hashMatches ? 'Payload tampered (hash mismatch)' : 'Cryptographically valid'),
    });

    if (!isBlockValid) {
      return {
        ok: false,
        brokenAt: i,
        reason: !prevMatches ? 'Previous hash link mismatch' : 'Ciphertext or IV altered (Hash mismatch)',
        nodes,
      };
    }
    expectedPrev = e.hash;
  }

  return { ok: true, nodes, totalVerified: entries.length };
}

// --- Emergency Recovery Kit Cryptography ---
export function generateRecoveryCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Base32-like without ambiguous I, O, 0, 1
  const array = new Uint8Array(24);
  let code = '';
  crypto.getRandomValues(array);
  for (let i = 0; i < 24; i++) {
    if (i > 0 && i % 4 === 0) code += '-';
    code += chars[array[i] % chars.length];
  }
  return code;
}

export async function wrapKey(rawKeyBytes, recoveryCode) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cleanCode = recoveryCode.replace(/[^A-Za-z0-9]/g, '').toUpperCase();
  const baseKey = await crypto.subtle.importKey(
    'raw', enc.encode(cleanCode), 'PBKDF2', false, ['deriveKey']
  );
  const wrappingKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, wrappingKey, rawKeyBytes
  );
  return {
    ciphertext: toB64(ciphertext),
    iv: toB64(iv),
    salt: toB64(salt),
  };
}

export async function unwrapKey(wrappedB64, ivB64, saltB64, recoveryCode) {
  const salt = fromB64(saltB64);
  const iv = fromB64(ivB64);
  const ciphertext = fromB64(wrappedB64);
  const cleanCode = recoveryCode.replace(/[^A-Za-z0-9]/g, '').toUpperCase();
  const baseKey = await crypto.subtle.importKey(
    'raw', enc.encode(cleanCode), 'PBKDF2', false, ['deriveKey']
  );
  const wrappingKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
  const decryptedBuf = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv }, wrappingKey, ciphertext
  );
  return crypto.subtle.importKey(
    'raw', decryptedBuf, 'AES-GCM', true, ['encrypt', 'decrypt']
  );
}
