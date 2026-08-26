# Security architecture — and its honest limits

This document is written to be read by someone evaluating the submission, not to be marketing copy. Where the architecture has a real limitation, it says so.

## The trust boundary, precisely

There are exactly two places plaintext journal content exists:

1. **Your browser's memory**, while you're typing and while displaying decrypted history.
2. **The Cloud Run gateway's memory**, for the duration of a single `/api/chat` request, because the Gemini API needs to read the text to respond to it.

It does not exist anywhere else. Specifically:

- Firestore never stores it — only AES-256-GCM ciphertext, an IV, and a hash.
- The gateway's logs never contain it — `console.error` calls only ever include status codes, never bodies.
- No database backup, export, or admin console view can recover plaintext for entries, because the plaintext was never written there.
- The Gemini API call is over TLS and is subject to Google's standard API data handling — this project doesn't and can't change that; it only minimizes what gets sent to the redaction the user opts into.

## What "zero-knowledge" means here — and what it doesn't

"Zero-knowledge" is used precisely for storage, not for AI processing:

- **True for storage**: the encryption key is derived from a user passphrase via PBKDF2 (150,000 iterations, SHA-256) entirely in the browser. It is never transmitted, never stored server-side, never recoverable by us. If our Firestore database were breached in full, an attacker gets ciphertext they cannot open.
- **Not true, and not claimed, for the live AI call**: Gemini has to read your message to respond to it. Any product claiming a cloud LLM can respond to your journal entry without ever seeing it is not being accurate. Attestory's actual claim is narrower and checkable: that plaintext touches exactly one additional hop (the stateless gateway), for exactly one request, and is never persisted or logged there.

This is a deliberate choice to be correct rather than to sound more private than the system actually is.

## Why a hash chain, and what it actually proves

Each entry stores `hash = SHA256(prevHash + ciphertext + iv)`, forming a chain back to a genesis value. This is the same primitive behind Git commits and Certificate Transparency logs, applied to a personal journal.

What it proves: if any entry — yours or, hypothetically, one altered by a compromised backend, a malicious admin, or an attacker with database write access — is changed after the fact, every hash from that point forward stops matching, and the client-side verification will name the exact entry where the chain broke.

What it does *not* prove: it doesn't prevent tampering, and it doesn't prove authorship (there's no signature tied to a hardware key or the user's real identity — that would be a reasonable v2). It's a detection mechanism, not a prevention mechanism, and this document says so rather than overselling it as "blockchain-secured" or similar.

## Data isolation

Firestore security rules require `request.auth.uid` to equal the `uid` segment of every document path under `/users/{uid}/...`, and deny all other access by default (`match /{document=**} { allow read, write: if false; }`). This is enforced by Firestore itself, independent of application code — even a bug in the frontend can't leak another user's documents, because the database rejects the request before it reaches app logic.

The backend's Firestore writes (the metadata-only audit log) go through the Admin SDK with a service account scoped by IAM, not through these rules, which is standard and appropriate for a trusted server context — the rules exist specifically to constrain the untrusted browser client.

## Key management

The Gemini API key is never in source control, a Docker image layer, or a Cloud Run environment variable. It's fetched from Secret Manager at request time using the attached service account's IAM permissions (`roles/secretmanager.secretAccessor`, scoped to that one secret) and cached in the gateway's memory for the life of the instance — not written to disk.

## What we'd do next with more time

Being direct about the roadmap, because a judge asking "what about X" deserves an answer already on the page:

- **Key recovery**: currently, a lost passphrase means lost access to past entries — by design, since recovery would require holding the key. A reasonable v2 is an optional recovery code generated once at setup, shown to the user exactly once, never stored.
- **Client-side redaction before the network hop**, not just server-side — reduces the TLS-hop exposure window further.
- **WebAuthn-bound entry signing** so the integrity ledger also proves authorship, not just non-tampering.
