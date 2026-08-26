# Attestory

*A personal Gemini journal that doesn't just claim to protect your data — it shows you exactly where the line between "private" and "processed by AI" sits, and lets you cryptographically prove your past entries haven't been altered.*

Built for the Google Cloud Gen AI Academy Ideathon — "Build a Secure Personal Gemini Journal" — on Firebase Auth, Cloud Firestore, Google Cloud Secret Manager, Cloud Run, and the Gemini API.

## Why this exists

Most "private AI journal" apps say some version of "your data is safe with us" without saying what that actually means. Either the AI reads your plaintext (so "private" is marketing) or the AI is thin/local-only (so the privacy is real but the product is weak). Attestory doesn't try to dodge that tradeoff — it makes the boundary visible and provable instead of hidden:

- **What's genuinely private:** stored entries. AES-256-GCM encrypted in your browser before they ever leave it. The key is derived from a passphrase that is never transmitted. Firestore holds ciphertext only — even a full database breach or subpoena yields nothing readable.
- **What's necessarily not private:** the single message you're actively sending to Gemini for a response, which exists as plaintext in your browser's memory and, for one request, in the Cloud Run gateway's memory. That's unavoidable — an LLM can't respond to text it can't read. Attestory just refuses to pretend otherwise, and guarantees that plaintext is never logged, never written to disk, and never persisted anywhere server-side.
- **What proves it wasn't tampered with:** every stored entry is chained to the previous one with a SHA-256 hash (`hash = SHA256(prevHash + ciphertext + iv)`). A "Verify integrity" button recomputes the whole chain client-side. If any entry, anywhere in the pipeline, is ever altered or deleted out of order, the chain breaks visibly and the user is told exactly where.

## Mandatory requirements — where each one lives

| Requirement | Implementation |
|---|---|
| User authentication via Firebase | `frontend/app.js` — Google sign-in via Firebase Auth |
| Multi-turn AI interaction with Gemini | `backend/server.js` `/api/chat` — sends the last 8 decrypted turns as context on every call |
| Isolated data storage in Firestore | `firestore.rules` — every read/write requires `request.auth.uid == uid` on the document path; backend writes only metadata, never content |
| Secure key management via Secret Manager | `backend/server.js` `getGeminiApiKey()` — fetched from Secret Manager at request time, never in an env var or source file |
| Original feature enhancement | Client-side zero-knowledge vault + hash-chained integrity ledger + security dashboard (see `SECURITY.md`) |

## Project layout

```
attestory/
  backend/            Cloud Run gateway (Node/Express) — stateless, talks to Gemini
    server.js
    package.json
    Dockerfile
    .env.example
  frontend/           Static web app — Firebase Auth, encryption, Firestore writes
    index.html
    app.js
    crypto.js
    style.css
  firestore.rules      Per-user isolation rules
  SECURITY.md           Judge-facing writeup of the architecture and its honest limits
```

## Setup

### 1. Firebase project
1. Create a project at console.firebase.google.com.
2. Enable **Authentication → Google** sign-in provider.
3. Enable **Firestore** (production mode).
4. Deploy the security rules: `firebase deploy --only firestore:rules` (after `firebase init` pointing at `firestore.rules`).
5. Copy your web app config into `frontend/app.js` (`firebaseConfig` object).

### 2. Gemini API key in Secret Manager
```bash
gcloud services enable secretmanager.googleapis.com run.googleapis.com

echo -n "YOUR_GEMINI_API_KEY" | gcloud secrets create gemini-api-key --data-file=-

# Grant your Cloud Run service account access
gcloud secrets add-iam-policy-binding gemini-api-key \
  --member="serviceAccount:YOUR_PROJECT_NUMBER-compute@developer.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

### 3. Deploy the backend gateway to Cloud Run
```bash
cd backend
gcloud run deploy attestory-gateway \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars GEMINI_SECRET_RESOURCE=projects/YOUR_PROJECT_NUMBER/secrets/gemini-api-key/versions/latest,ALLOWED_ORIGIN=https://YOUR_FIREBASE_HOSTING_DOMAIN
```
Copy the resulting service URL into `GATEWAY_URL` in `frontend/app.js`.

`--allow-unauthenticated` is correct here — auth happens at the application layer (Firebase ID token verified inside `server.js`), not at the Cloud Run IAM layer, because the frontend calls this service directly from the browser.

### 4. Deploy the frontend
Simplest path — Firebase Hosting:
```bash
firebase init hosting   # public directory: frontend
firebase deploy --only hosting
```

### 5. Try it
Open the hosting URL, sign in with Google, set a passphrase, write an entry, get a Gemini reply, then hit **Verify integrity** to see the hash chain check pass — and try manually editing a document in the Firestore console to see it correctly fail.

## What "at least one original feature" means here

Two, actually, working together as one coherent story rather than two bolted-on gimmicks:

1. **Zero-knowledge vault** — entries are unreadable to us, by construction, not by promise.
2. **Integrity ledger** — entries are tamper-evident, so "private" doesn't quietly become "private, and also we could have edited your journal and you'd never know."

See `SECURITY.md` for the full technical writeup, including the parts we're deliberately *not* claiming.
