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

const path = require('path');
const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const { SecretManagerServiceClient } = require('@google-cloud/secret-manager');

const app = express();
app.use(cors({ origin: process.env.ALLOWED_ORIGIN || true }));
app.use(express.json({ limit: '256kb' })); // journal turns are short; cap payload size defensively

// Serve the frontend from this same Cloud Run service, so the one public URL
// submitted for the Ideathon is a real, working, Cloud Run-hosted app — not
// just a bare API. app.js now calls the API with relative paths (same origin),
// so no GATEWAY_URL/CORS config is needed for the deployed app.
app.use(express.static(path.join(__dirname, 'public')));

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
    const contents = [
      ...safeHistory.map((turn) => ({
        role: turn.role === 'model' ? 'model' : 'user',
        parts: [{ text: String(turn.text || '').slice(0, 4000) }],
      })),
      { role: 'user', parts: [{ text: outgoing }] },
    ];

    const geminiRes = await fetch(
      'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent',
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
      console.error('Gemini error', geminiRes.status); // status only — never log message content
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

// ---- Weekly Digest endpoint ----
app.post('/api/digest', requireAuth, async (req, res) => {
  const { entries, customFocus } = req.body || {};

  if (!Array.isArray(entries) || entries.length === 0) {
    return res.status(400).json({ error: 'entries is required and must be non-empty' });
  }

  // Sanitization and Cap
  const sanitized = entries
    .filter((e) => e && typeof e.content === 'string' && e.content.trim())
    .slice(0, 50)
    .map((e, idx) => ({
      index: idx + 1,
      date: new Date(e.timestamp || Date.now()).toLocaleDateString('en-US', {
        weekday: 'short',
        month: 'short',
        day: 'numeric',
      }),
      author: e.role === 'user' ? 'Journal Author' : 'AI Companion',
      text: e.content.substring(0, 1500),
    }));

  if (sanitized.length === 0) {
    return res.status(400).json({ error: 'No valid journal content entries found' });
  }

  const userPrompt = `Here is the journal activity for the past week:
${JSON.stringify(sanitized, null, 2)}

${customFocus ? `Special Focus Request: ${customFocus}` : ''}

Please generate the weekly reflection digest.`;

  try {
    const apiKey = await getGeminiApiKey();
    const geminiRes = await fetch(
      'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-goog-api-key': apiKey },
        body: JSON.stringify({
          contents: [{ role: 'user', parts: [{ text: userPrompt }] }],
          systemInstruction: {
            parts: [{
              text: `You are Attestory's Weekly Reflection Digest synthesiser.
You are given a chronological record of the user's decrypted journal entries from the past week.
Analyze these personal reflections to produce a short, warm, pattern-noticing summary.
Focus on:
1. Recurring themes or recurring topics of interest.
2. Emotional trajectory and mood shifts across the days.
3. Personal wins, challenges overcome, or subtle insights worth celebrating.
4. Gentle, encouraging closing thought.

STRICT CONSTRAINTS:
- Do NOT provide clinical, psychological, or medical diagnoses.
- Keep tone deeply empathetic, grounded, observational, and warm.
- Produce a structured JSON response matching the required schema.`,
            }],
          },
          generationConfig: {
            responseMimeType: 'application/json',
            responseSchema: {
              type: 'object',
              properties: {
                digest: {
                  type: 'string',
                  description: 'A 2-3 paragraph reflective summary of the week.',
                },
                keyThemes: {
                  type: 'array',
                  items: { type: 'string' },
                  description: '3-4 short phrases capturing recurring themes.',
                },
                moodInsights: {
                  type: 'string',
                  description: 'Observations on the emotional trajectory.',
                },
                continuityNotes: {
                  type: 'string',
                  description: 'Continuity threads connecting this week to the past.',
                },
              },
              required: ['digest', 'keyThemes', 'moodInsights', 'continuityNotes'],
            },
            maxOutputTokens: 800,
            temperature: 0.7,
          },
        }),
      }
    );

    if (!geminiRes.ok) {
      const errText = await geminiRes.text();
      console.error('Gemini error status:', geminiRes.status, 'body:', errText);
      return res.status(502).json({ error: 'Gemini request failed', status: geminiRes.status });
    }

    const data = await geminiRes.json();
    const replyText = data?.candidates?.[0]?.content?.parts?.map((p) => p.text).join('') || '{}';
    
    let digestData;
    try {
      digestData = JSON.parse(replyText);
    } catch {
      digestData = {
        digest: replyText,
        keyThemes: [],
        moodInsights: '',
        continuityNotes: ''
      };
    }

    // Write to audit log
    await db.collection('users').doc(req.uid).collection('auditLog').add({
      action: 'digest_generation',
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
    });

    return res.json({
      digest: digestData.digest,
      keyThemes: digestData.keyThemes,
      moodInsights: digestData.moodInsights,
      continuityNotes: digestData.continuityNotes,
      model: 'gemini-2.5-flash',
    });
  } catch (err) {
    console.error('digest handler error:', err.message);
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

// SPA fallback: any other GET request that isn't /api/* or a static file
// serves index.html, so a direct link to the deployed URL always loads the app.
app.get(/^(?!\/api).*/, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const port = process.env.PORT || 8080;
app.listen(port, () => console.log(`Attestory gateway listening on ${port}`));
