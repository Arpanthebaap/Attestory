import { initializeApp } from 'https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js';
import {
  getAuth, GoogleAuthProvider, signInWithPopup, signOut, onAuthStateChanged,
} from 'https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js';
import {
  getFirestore, doc, getDoc, setDoc, collection, addDoc, query, orderBy, getDocs,
} from 'https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore.js';
import {
  deriveKey, randomSaltB64, encryptText, decryptText,
  computeEntryHash, verifyChain, GENESIS_HASH,
} from './crypto.js';

// --- Fill these in from your Firebase project settings (Project settings > General) ---
const firebaseConfig = {
  apiKey: 'AIzaSyDg7qxvY7bcVQl0sKy1oaDOXebxBkezjrs',
  authDomain: 'attestory-539601.firebaseapp.com',
  projectId: 'attestory-539601',
  storageBucket: 'attestory-539601.firebasestorage.app',
  messagingSenderId: '42612879787',
  appId: '1:42612879787:web:92e5abab33fb28cc3b62ee',
};
// URL of your deployed Cloud Run gateway (backend/), e.g. https://attestory-gateway-xyz.a.run.app
const GATEWAY_URL = 'https://attestory-gateway-42612879787.us-central1.run.app';

const fbApp = initializeApp(firebaseConfig);
const auth = getAuth(fbApp);
const db = getFirestore(fbApp);

let currentUser = null;
let vaultKey = null;      // AES-GCM CryptoKey, lives only in memory
let lastHash = GENESIS_HASH;
let decryptedTurns = [];  // recent plaintext turns, in memory only, for Gemini context

const $ = (id) => document.getElementById(id);

// ---------- Auth ----------
$('signin-btn').onclick = () => signInWithPopup(auth, new GoogleAuthProvider());
$('signout-btn').onclick = () => { vaultKey = null; lastHash = GENESIS_HASH; decryptedTurns = []; signOut(auth); };

onAuthStateChanged(auth, async (user) => {
  currentUser = user;
  if (user) {
    $('header-signed-out').classList.add('hidden');
    $('header-signed-in').classList.remove('hidden');
    $('body-signed-out').classList.add('hidden');
    $('body-signed-in').classList.remove('hidden');
    $('user-email').textContent = user.email;
    await promptUnlock();
  } else {
    $('header-signed-out').classList.remove('hidden');
    $('header-signed-in').classList.add('hidden');
    $('body-signed-out').classList.remove('hidden');
    $('body-signed-in').classList.add('hidden');
  }
});

// ---------- Vault unlock (passphrase never leaves the browser) ----------
async function promptUnlock() {
  const metaRef = doc(db, 'users', currentUser.uid, 'keyMeta', 'salt');
  const metaSnap = await getDoc(metaRef);
  let salt;
  if (metaSnap.exists()) {
    salt = metaSnap.data().salt;
    $('unlock-title').textContent = 'Enter your journal passphrase';
  } else {
    salt = randomSaltB64();
    await setDoc(metaRef, { salt, createdAt: Date.now() });
    $('unlock-title').textContent = 'Set a journal passphrase (first time)';
  }
  $('unlock-modal').classList.remove('hidden');
  $('unlock-form').onsubmit = async (e) => {
    e.preventDefault();
    const passphrase = $('passphrase-input').value;
    vaultKey = await deriveKey(passphrase, salt);
    $('unlock-modal').classList.add('hidden');
    $('passphrase-input').value = '';
    await loadEntries();
  };
}

// ---------- Load + decrypt entries, rebuild hash chain tail ----------
async function loadEntries() {
  const entriesRef = collection(db, 'users', currentUser.uid, 'entries');
  const q = query(entriesRef, orderBy('createdAt', 'asc'));
  const snap = await getDocs(q);

  const list = $('entries-list');
  list.innerHTML = '';
  lastHash = GENESIS_HASH;
  decryptedTurns = [];

  const chainEntries = [];
  for (const docSnap of snap.docs) {
    const d = docSnap.data();
    chainEntries.push({ ciphertext: d.ciphertext, iv: d.iv, prevHash: d.prevHash, hash: d.hash });
    lastHash = d.hash;
    try {
      const plaintext = await decryptText(vaultKey, d.ciphertext, d.iv);
      const parsed = JSON.parse(plaintext); // { role: 'user'|'model', text }
      decryptedTurns.push(parsed);
      const row = document.createElement('div');
      row.className = `turn turn-${parsed.role}`;
      row.textContent = parsed.text;
      list.appendChild(row);
    } catch (err) {
      const row = document.createElement('div');
      row.className = 'turn turn-error';
      row.textContent = '[could not decrypt — wrong passphrase?]';
      list.appendChild(row);
    }
  }
  list.scrollTop = list.scrollHeight;
  window.__chainEntries = chainEntries; // used by verify button
}

// ---------- Store one turn as an encrypted, chained entry ----------
async function storeTurn(role, text) {
  const payload = JSON.stringify({ role, text });
  const { ciphertext, iv } = await encryptText(vaultKey, payload);
  const hash = await computeEntryHash(lastHash, ciphertext, iv);
  const entriesRef = collection(db, 'users', currentUser.uid, 'entries');
  await addDoc(entriesRef, { ciphertext, iv, prevHash: lastHash, hash, createdAt: Date.now() });
  lastHash = hash;
  decryptedTurns.push({ role, text });
}

// ---------- Chat ----------
$('chat-form').onsubmit = async (e) => {
  e.preventDefault();
  if (!vaultKey) return;
  const input = $('chat-input');
  const message = input.value.trim();
  if (!message) return;
  input.value = '';
  input.disabled = true;

  const list = $('entries-list');
  const userRow = document.createElement('div');
  userRow.className = 'turn turn-user';
  userRow.textContent = message;
  list.appendChild(userRow);
  list.scrollTop = list.scrollHeight;

  await storeTurn('user', message);

  try {
    const idToken = await currentUser.getIdToken();
    const res = await fetch(`${GATEWAY_URL}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${idToken}` },
      body: JSON.stringify({
        message,
        history: decryptedTurns.slice(-8).map((t) => ({ role: t.role, text: t.text })),
        redactPii: $('redact-toggle').checked,
      }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'request failed');

    if (data.redacted && data.redacted.length) {
      const note = document.createElement('div');
      note.className = 'turn turn-note';
      note.textContent = `Redacted before sending to Gemini: ${data.redacted.join(', ')}`;
      list.appendChild(note);
    }

    const modelRow = document.createElement('div');
    modelRow.className = 'turn turn-model';
    modelRow.textContent = data.reply;
    list.appendChild(modelRow);
    list.scrollTop = list.scrollHeight;

    await storeTurn('model', data.reply);
  } catch (err) {
    const errRow = document.createElement('div');
    errRow.className = 'turn turn-error';
    errRow.textContent = `Something went wrong: ${err.message}`;
    list.appendChild(errRow);
  } finally {
    input.disabled = false;
    input.focus();
  }
};

// ---------- Integrity verification ----------
$('verify-btn').onclick = async () => {
  const result = await verifyChain(window.__chainEntries || []);
  const out = $('verify-result');
  if (result.ok) {
    out.textContent = 'Verified: every entry hash-chains correctly. Nothing has been altered.';
    out.className = 'verify-ok';
  } else {
    out.textContent = `Integrity check failed at entry #${result.brokenAt + 1} (${result.reason}).`;
    out.className = 'verify-fail';
  }
};

// ---------- Security dashboard: audit log (metadata only) ----------
$('dashboard-btn').onclick = async () => {
  $('dashboard-modal').classList.remove('hidden');
  const idToken = await currentUser.getIdToken();
  const res = await fetch(`${GATEWAY_URL}/api/audit`, { headers: { Authorization: `Bearer ${idToken}` } });
  const data = await res.json();
  const list = $('audit-list');
  list.innerHTML = '';
  for (const entry of data.entries || []) {
    const row = document.createElement('div');
    row.className = 'audit-row';
    const when = entry.timestamp ? new Date(entry.timestamp._seconds * 1000).toLocaleString() : '—';
    row.textContent = `${when} — sent to Gemini${entry.redacted?.length ? ` (redacted: ${entry.redacted.join(', ')})` : ''}`;
    list.appendChild(row);
  }
};
$('close-dashboard').onclick = () => $('dashboard-modal').classList.add('hidden');
