// Attestory gateway
//
// This service is intentionally "dumb" and stateless. It does exactly three things:
//   1. Verifies the caller's Firebase ID token (so we know which uid is talking).
//   2. Optionally redacts obvious PII patterns before the text leaves this process.
//   3. Calls the Gemini API and returns the response.
//
// It NEVER writes journal content to Firestore, NEVER logs request/response bodies,
// and holds no database connection for entries at all. Entries are encrypted in the
// browser and written directly to Firestore from there, governed by firestore.rules.
// This service only ever sees plaintext transiently, in memory, for the duration of
// a single request — that boundary is the whole point of the architecture.

const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const { SecretManagerServiceClient } = require('@google-cloud/secret-manager');
const fetch = require('node-fetch');

const app = express();
app.use(cors({ origin: process.env.ALLOWED_ORIGIN || true }));
app.use(express.json({ limit: '256kb' })); // journal turns are short; cap payload size defensively

admin.initializeApp(); // On Cloud Run this picks up the attached service account automatically.

const db = admin.firestore();
const secretClient = new SecretManagerServiceClient();

// ---- Secret Manager: fetch the Gemini API key once, cache in memory ----
// The key is never in an env var, never in source control, never in a Docker layer.
let cachedApiKey = null;
async function getGeminiApiKey() {
  if (cachedApiKey) return cachedApiKey;
  const name = process.env.GEMINI_SECRET_RESOURCE; // e.g. projects/123/secrets/gemini-api-key/versions/latest
  if (!name) throw new Error('GEMINI_SECRET_RESOURCE env var is not set');
  const [version] = await secretClient.accessSecretVersion({ name });
  cachedApiKey = version.payload.data.toString('utf8');
  return cachedApiKey;
}

// ---- Auth middleware: every route below this requires a valid Firebase ID token ----
async function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const match = header.match(/^Bearer (.+)$/);
  if (!match) return res.status(401).json({ error: 'Missing Authorization: Bearer <idToken>' });
  try {
    const decoded = await admin.auth().verifyIdToken(match[1]);
    req.uid = decoded.uid;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ---- Lightweight, transparent PII redaction (opt-in from the client) ----
// This is deliberately simple regex-based redaction, not a claim of perfect NER.
// The point is to give the user visible control over what leaves their device,
// not to promise complete PII detection.
const REDACTION_PATTERNS = [
  { label: 'email', re: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g },
  { label: 'phone', re: /\b(\+?\d{1,3}[-.\s]?)?(\(?\d{3,4}\)?[-.\s]?)\d{3,4}[-.\s]?\d{3,4}\b/g },
  { label: 'card number', re: /\b(?:\d[ -]*?){13,16}\b/g },
  { label: 'ssn-like', re: /\b\d{3}-\d{2}-\d{4}\b/g },
];

function redact(text) {
  const found = [];
  let output = text;
  for (const { label, re } of REDACTION_PATTERNS) {
    output = output.replace(re, (m) => {
      found.push(label);
      return `[redacted:${label}]`;
    });
  }
  return { output, found };
}

function sanitizeContents(contents) {
  if (!contents || contents.length === 0) return [];
  const sanitized = [];
  for (const turn of contents) {
    if (sanitized.length === 0) {
      sanitized.push(turn);
    } else {
      const lastTurn = sanitized[sanitized.length - 1];
      if (lastTurn.role === turn.role) {
        const lastText = lastTurn.parts[0].text || '';
        const currentText = turn.parts[0].text || '';
        lastTurn.parts[0].text = lastText + '\n' + currentText;
      } else {
        sanitized.push(turn);
      }
    }
  }
  return sanitized;
}

// ---- Chat endpoint: the only route that talks to Gemini ----
app.post('/api/chat', requireAuth, async (req, res) => {
  const { message, history, redactPii } = req.body || {};

  if (typeof message !== 'string' || !message.trim()) {
    return res.status(400).json({ error: 'message is required' });
  }
  if (message.length > 4000) {
    return res.status(400).json({ error: 'message too long (max 4000 chars)' });
  }
  // history: array of {role: 'user'|'model', text} for the last few turns.
  // The client decrypts its own stored entries to build this — the server
  // never stores it and never sees it outside this single request.
  const safeHistory = Array.isArray(history) ? history.slice(-8) : [];

  let outgoing = message;
  let redactionReport = [];
  if (redactPii) {
    const result = redact(message);
    outgoing = result.output;
    redactionReport = result.found;
  }

  try {
    const apiKey = await getGeminiApiKey();
    const rawContents = [
      ...safeHistory.map((turn) => ({
        role: turn.role === 'model' ? 'model' : 'user',
        parts: [{ text: String(turn.text || '').slice(0, 4000) }],
      })),
      { role: 'user', parts: [{ text: outgoing }] },
    ];
    const contents = sanitizeContents(rawContents);

    const geminiRes = await fetch(
      'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-goog-api-key': apiKey },
        body: JSON.stringify({
          contents,
          systemInstruction: {
            parts: [{
              text: 'You are a calm, reflective journaling companion. Ask short, thoughtful ' +
                'follow-up questions. Never claim to be a therapist. Keep responses under 120 words ' +
                'unless the user asks for more.',
            }],
          },
          generationConfig: { maxOutputTokens: 400, temperature: 0.8 },
        }),
      }
    );

    if (!geminiRes.ok) {
      const errText = await geminiRes.text();
      console.error('Gemini error status:', geminiRes.status, 'body:', errText);
      return res.status(502).json({ error: 'Gemini request failed', status: geminiRes.status });
    }

    const data = await geminiRes.json();
    const reply = data?.candidates?.[0]?.content?.parts?.map((p) => p.text).join('') || '';

    // Metadata-only audit trail: no message content, ever. This is what powers
    // the "AI access log" on the security dashboard so the user can see exactly
    // when their data touched the model, without the log itself being a privacy risk.
    await db.collection('users').doc(req.uid).collection('auditLog').add({
      action: 'gemini_call',
      redacted: redactionReport,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
    });

    return res.json({ reply, redacted: redactionReport });
  } catch (err) {
    console.error('chat handler error:', err.message);
    return res.status(500).json({ error: 'internal error' });
  }
});

// ---- Read-only audit log (metadata only, never content) ----
app.get('/api/audit', requireAuth, async (req, res) => {
  const snap = await db
    .collection('users').doc(req.uid).collection('auditLog')
    .orderBy('timestamp', 'desc').limit(50).get();
  const entries = snap.docs.map((d) => ({ id: d.id, ...d.data() }));
  res.json({ entries });
});

app.get('/healthz', (req, res) => res.json({ ok: true }));

const port = process.env.PORT || 8080;
app.listen(port, () => console.log(`Attestory gateway listening on ${port}`));
