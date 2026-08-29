# Attestory

*A personal Gemini journal that doesn't just claim to protect your data — it shows you exactly where the line between "private" and "processed by AI" sits, and lets you cryptographically prove your past entries haven't been altered.*

Built for the Google Cloud Gen AI Academy Ideathon — **"Build a Secure Personal Gemini Journal"** — on Firebase Auth, Cloud Firestore, Google Cloud Secret Manager, Cloud Run, and the Gemini API.

- 🔗 **Live app**: https://attestory-gateway-42612879787.us-central1.run.app/
- 🔗 **Repo**: https://github.com/Arpanthebaap/Attestory

## Why this exists

Most "private AI journal" apps say some version of "your data is safe with us" without saying what that actually means. Either the AI reads your plaintext (so "private" is marketing) or the AI is thin/local-only (so the privacy is real but the product is weak). Attestory doesn't try to dodge that tradeoff — it makes the boundary visible and provable instead of hidden:

- **What's genuinely private:** stored entries. AES-256-GCM encrypted in your browser before they ever leave it. The key is derived from a passphrase (or recovery code) that is never transmitted. Firestore holds ciphertext only — even a full database breach or subpoena yields nothing readable.
- **What's necessarily not private:** the single message you're actively sending to Gemini for a response, which exists as plaintext in your browser's memory and, for one request, in the Cloud Run gateway's memory. That's unavoidable — an LLM can't respond to text it can't read. Attestory refuses to pretend otherwise, and guarantees that plaintext is never logged, never written to disk, and never persisted anywhere server-side.
- **What proves it wasn't tampered with:** every stored entry is chained to the previous one with a SHA-256 hash (`hash = SHA256(prevHash + ciphertext + iv)`). The **Proof Chain Explorer** recomputes the whole chain client-side, including a "Simulate Database Tamper" demo button so you can watch detection happen live.

## Mandatory requirements — where each one lives

| Requirement | Implementation |
|---|---|
| User authentication via Firebase | Google sign-in via Firebase Auth |
| Multi-turn AI interaction with Gemini | `/api/chat` — sends recent decrypted turns as context on every call; five selectable AI personas (Socratic Inquiry, Brainstorming, Stoic Guide, Executive Clarity, Gratitude Coach) change the system prompt, not the security model |
| Isolated data storage in Firestore | `firestore.rules` — every read/write requires `request.auth.uid == uid` on the document path; backend writes only metadata, never content |
| Secure key management via Secret Manager | Gemini API key fetched from Secret Manager at request time, cached in memory only, never in an env var or source file |

## Feature enhancements — built beyond the base spec

| Feature | What it does |
|---|---|
| **Zero-knowledge vault** | AES-256-GCM encryption, client-side, before anything leaves the browser. PBKDF2 key derivation, 150,000 rounds. |
| **Tamper-evident proof chain** | SHA-256 hash-chained entries; live verification and tamper simulation in the UI. |
| **Recovery Kit** | A one-time-shown recovery code lets you restore your vault key if you forget your passphrase — without us ever storing the passphrase or the plaintext key. Closes the biggest real usability gap of zero-knowledge storage. |
| **Weekly Cognitive Digest** | Entries are decrypted locally and sent to Gemini with a dedicated reflection-synthesis prompt; the digest is encrypted and hash-chained exactly like any other entry before storage. |
| **PII Redaction Shield** | Opt-in, transparent, regex-based redaction of emails, phone numbers, and card numbers before anything is sent to Gemini, with a visible count of what was caught. |
| **Export & data portability** | Download a decrypted Markdown copy for your own records, or a raw encrypted JSON backup (ciphertext, IVs, salts, and the full hash chain) for cold storage or independent verification. |
| **Security & Governance dashboard** | A live, in-app audit view of every claim above — encryption status, key derivation parameters, Firestore isolation, Secret Manager usage, and a metadata-only Gemini access log (timestamps and redaction counts, never message content). |

## How Google AI Studio was used

Per the Ideathon's Phase 1–3 structure:

- **Phase 1 (constitution):** Google AI Studio's Custom Instructions were configured with production-grade security directives — structured threat modeling before code generation, OWASP Top 10 and OWASP LLM Top 10 coding standards, Firestore/Firebase Auth isolation rules, and a zero-hardcoded-secrets policy requiring Secret Manager retrieval.
- **Phase 3 (feature builds):** the Recovery Kit and Weekly Cognitive Digest were designed and generated in Google AI Studio's Build Mode under that same constitution, then merged into this production codebase so the app kept its existing Secret Manager wiring, Firestore rules, and live Cloud Run URL rather than forking into a separate deployment.

This service also carries the required `dev-tutorial=cloud-run-ai-challenge` resource label for automated challenge verification.

## Project layout

```
attestory/
  backend/
    server.js       Stateless Cloud Run gateway — auth verification, Gemini calls, Secret Manager
    package.json
    Dockerfile
    public/          Frontend served from the same Cloud Run service (index.html, app.js, crypto.js, style.css)
  frontend/          Source copies of the same static files, kept for local development
  firestore.rules     Per-user isolation rules
  SECURITY.md          Full technical writeup, including honest limitations and what's on the roadmap
```

## Setup

### 1. Firebase project
1. Create a project at console.firebase.google.com.
2. Enable **Authentication → Google** sign-in provider.
3. Enable **Firestore** (production mode) and deploy `firestore.rules`.
4. Copy your web app config into `backend/public/app.js` (`firebaseConfig` object).
5. Add your Cloud Run service's `*.run.app` domain under **Authentication → Settings → Authorized domains** — sign-in fails silently on that URL otherwise.

### 2. Gemini API key in Secret Manager
```bash
gcloud services enable secretmanager.googleapis.com run.googleapis.com
echo -n "YOUR_GEMINI_API_KEY" | gcloud secrets create gemini-api-key --data-file=-
gcloud secrets add-iam-policy-binding gemini-api-key \
  --member="serviceAccount:YOUR_PROJECT_NUMBER-compute@developer.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

### 3. Deploy — single Cloud Run service serves both frontend and API
```bash
cd backend
gcloud run deploy attestory-gateway \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --min-instances 0 \
  --max-instances 1 \
  --memory 256Mi \
  --labels dev-tutorial=cloud-run-ai-challenge \
  --set-env-vars GEMINI_SECRET_RESOURCE=projects/YOUR_PROJECT_NUMBER/secrets/gemini-api-key/versions/latest
```

### 4. Try it
Open the deployed URL, sign in with Google, set a passphrase (save the recovery code that's shown), write an entry, get a Gemini reply, generate a Weekly Digest, then open the Proof Chain Explorer and try "Simulate Database Tamper" to watch integrity verification catch it in real time.

See `SECURITY.md` for the full architecture writeup, including what we're deliberately *not* claiming.
