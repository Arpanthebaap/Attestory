# ATTESTORY SECURITY CONSTITUTION & SYSTEM DIRECTIVES

> **Scope**: Foundational security engineering directives, threat models, cryptographic invariants, and database isolation rules for Attestory and Google AI Studio builds.

---

## 1. Zero-Trust Threat Model & Architectural Invariants

1. **Client-Side Zero-Knowledge Encryption (E2EE)**
   - All journal entries, notes, and personal reflections **MUST** be encrypted in the client browser using **AES-256-GCM** before leaving the device.
   - Encryption keys **MUST** be derived locally using **PBKDF2-HMAC-SHA-256** (minimum 100,000+ iterations) from user passphrases or wrapped recovery keys.
   - Keys **MUST NEVER** be transmitted over the wire, stored in cookies, sent to the backend server, or written into database storage.

2. **Cryptographic Tamper-Evidence (Hash Chaining)**
   - Every journal entry **MUST** compute a deterministic cryptographic hash:
     $$\text{Hash}_n = \text{SHA-256}(\text{Hash}_{n-1} \parallel \text{Ciphertext}_n \parallel \text{IV}_n)$$
   - The genesis block begins at $\text{Hash}_0 = 0^{64}$.
   - Verification covers ciphertext and IVs directly, allowing zero-knowledge integrity verification even before vault unlocking.
   - If any entry is injected, deleted, reordered, or modified, the hash verification chain immediately breaks at that exact index.

3. **Strict Database Isolation & Zero Cross-User Leakage**
   - Cloud Firestore security rules **MUST** enforce path-based authorization at `/users/{uid}/**`.
   - Any request where `request.auth.uid != uid` is rejected at the database engine level.
   - Schema enforcement: reject any payload containing plaintext-shaped keys (e.g. `!('plaintext' in request.resource.data)`).

4. **Secret Management & Server-Side Proxying**
   - The Gemini API key **MUST NEVER** exist in client bundles, HTML, local storage, or public repositories.
   - All Gemini interactions are proxied through an authenticated server-side gateway (`/api/chat`, `/api/digest`).
   - The gateway fetches keys via **Google Cloud Secret Manager** or server-side environment variables (`GEMINI_API_KEY`), caching safely in ephemeral memory.
   - The gateway requires valid Firebase ID Tokens (`Authorization: Bearer <idToken>`) on every endpoint.

5. **Client-Side PII Redaction & Data Minimization**
   - Users maintain granular control over outbound data to AI models.
   - Obvious PII (emails, phone numbers, credit card numbers, SSNs, API tokens) is redacted locally before payload serialization.
   - Transparent reporting surfaces exact redacted entity types without storing or logging raw message strings.

6. **Metadata-Only AI Audit Trails**
   - Backend logging **MUST NEVER** write prompt bodies, user thoughts, or Gemini responses to server logs or persistent databases.
   - Audit logs store strictly operational metadata: `{ timestamp, action, uid, redactedTypes, latencyMs }`.

---

## 2. Secure Coding Standards & Defensive Guidelines

- **Input Validation**: Sanitize and enforce maximum character budgets (e.g., max 4000 characters per chat turn) and rate limits.
- **Web Crypto API**: Use native `window.crypto.subtle` for all cryptographic operations. No insecure third-party crypto polyfills.
- **CSP & Iframe Resilience**: Defend against XSS, clickjacking, and unauthorized origin access using strict headers and origin verification.
- **Graceful Degradation**: If cloud services or tokens are unreachable, provide safe offline/local session encryption so user reflections are never lost.
