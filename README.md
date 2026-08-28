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
| Emergency Recovery Kit | `frontend/crypto.js` `wrapKey`/`unwrapKey` — client-side PBKDF2 vault key wrapping to recover access without server exposure |
| Weekly Reflection Digest | `backend/server.js` `/api/digest` — secure local decryption and structured summary generation via Gemini API |
| Original feature enhancement | Client-side zero-knowledge vault + hash-chained integrity ledger + emergency recovery + weekly reflections (see `SECURITY.md`) |

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

### 3. Deploy everything as one Cloud Run service (this is the submission link)

The Ideathon rules ask specifically for a prototype "deployed on Cloud Run" — so `backend/` now serves both the frontend (from `backend/public/`) and the API from a single Cloud Run service. This is the URL you put in the submission form.

```bash
cd backend
gcloud run deploy attestory-gateway \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --min-instances 0 \
  --max-instances 1 \
  --memory 256Mi \
  --set-env-vars GEMINI_SECRET_RESOURCE=projects/YOUR_PROJECT_NUMBER/secrets/gemini-api-key/versions/latest
```

`--allow-unauthenticated` is correct here — auth happens at the application layer (Firebase ID token verified inside `server.js`), not at the Cloud Run IAM layer.

Before this works, edit `backend/public/app.js` and fill in your real `firebaseConfig` (Firebase project settings → General → your web app), then redeploy.

**Important**: Firebase Auth only allows sign-in popups from domains you've explicitly authorized. In the Firebase console → Authentication → Settings → Authorized domains, add your Cloud Run domain (the `*.run.app` hostname from the URL above) — otherwise Google sign-in will fail silently on that URL even though it works fine on `localhost`.

### 4. (Optional) Also deploy the frontend to Firebase Hosting
Not required for submission, but useful as a second, faster-loading mirror:
```bash
firebase init hosting   # public directory: frontend
firebase deploy --only hosting
```
Note this copy still needs its own `GATEWAY_URL` set to your Cloud Run URL in `frontend/app.js`, since it's a different origin than the API.

### 5. Try it
Open the hosting URL, sign in with Google, set a passphrase, write an entry, get a Gemini reply, then hit **Verify integrity** to see the hash chain check pass — and try manually editing a document in the Firestore console to see it correctly fail.

## What "at least one original feature" means here

Four, actually, working together as one coherent story:

1. **Zero-knowledge vault** — entries are unreadable to us, by construction, not by promise.
2. **Integrity ledger** — entries are tamper-evident, so "private" doesn't quietly become "private, and also we could have edited your journal and you'd never know."
3. **Emergency Recovery Kit** — allows recovering access to your encrypted entries if you forget your passphrase, using a client-side generated and wrapped key.
4. **Weekly Reflection Digest** — generates warm, pattern-noticing reflections on past entries decrypted locally and summarized by Gemini.

See `SECURITY.md` for the full technical writeup, including the parts we're deliberately *not* claiming.
