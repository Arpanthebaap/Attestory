// Attestory crypto module
//
// Everything in this file runs in the browser. The derived encryption key
// never leaves this module — it is not sent to the backend, not written to
// Firestore, and not persisted anywhere except sessionStorage-backed memory
// for the duration of the tab. If the user closes the tab, they must
// re-enter their passphrase. That's the tradeoff for genuine zero-knowledge
// storage: we cannot offer "forgot password" recovery for past entries,
// because recovery would require us to hold the key.

const enc = new TextEncoder();
const dec = new TextDecoder();

function toB64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function fromB64(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)).buffer;
}

export function randomSaltB64() {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return toB64(salt);
}

// Derive an AES-GCM key from the user's passphrase + a per-user salt (stored
// in Firestore under keyMeta — the salt is not secret, only the passphrase is).
export async function deriveKey(passphrase, saltB64) {
  const baseKey = await crypto.subtle.importKey(
    'raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: fromB64(saltB64), iterations: 150000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
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

// --- Integrity ledger ---
// Each entry's hash = SHA-256(previousHash + ciphertext + iv). Because the
// hash covers the CIPHERTEXT (not plaintext), verification works even without
// the passphrase — you can prove the chain hasn't been tampered with before
// you've even unlocked the vault. If any stored entry, in any order, is
// edited or deleted, every hash after it stops matching and the UI flags
// exactly where the chain breaks.
export async function sha256Hex(str) {
  const hashBuf = await crypto.subtle.digest('SHA-256', enc.encode(str));
  return Array.from(new Uint8Array(hashBuf)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function computeEntryHash(previousHash, ciphertextB64, ivB64) {
  return sha256Hex(`${previousHash}|${ciphertextB64}|${ivB64}`);
}

export const GENESIS_HASH = '0'.repeat(64);

// Verifies a full ordered list of entries [{ciphertext, iv, prevHash, hash}, ...].
// Returns { ok: true } or { ok: false, brokenAt: index } for the UI to surface.
export async function verifyChain(entries) {
  let expectedPrev = GENESIS_HASH;
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    if (e.prevHash !== expectedPrev) return { ok: false, brokenAt: i, reason: 'prevHash mismatch' };
    const recomputed = await computeEntryHash(e.prevHash, e.ciphertext, e.iv);
    if (recomputed !== e.hash) return { ok: false, brokenAt: i, reason: 'hash mismatch (content altered)' };
    expectedPrev = e.hash;
  }
  return { ok: true };
}
