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
  generateRecoveryCode, wrapKey, unwrapKey,
} from './crypto.js';

// --- Fill these in from your Firebase project settings (Project settings > General) ---
const firebaseConfig = {
  apiKey: 'YOUR_FIREBASE_API_KEY',
  authDomain: 'YOUR_PROJECT.firebaseapp.com',
  projectId: 'YOUR_PROJECT_ID',
  storageBucket: 'YOUR_PROJECT.appspot.com',
  messagingSenderId: 'YOUR_SENDER_ID',
  appId: 'YOUR_APP_ID',
};
// URL of your deployed Cloud Run gateway (backend/), e.g. https://attestory-gateway-xyz.a.run.app
const GATEWAY_URL = 'YOUR_CLOUD_RUN_URL';

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
    $('signed-out').classList.add('hidden');
    $('signed-in').classList.remove('hidden');
    $('user-email').textContent = user.email;
    await promptUnlock();
  } else {
    $('signed-out').classList.remove('hidden');
    $('signed-in').classList.add('hidden');
  }
});

// ---------- Vault unlock (passphrase never leaves the browser) ----------
let allDecryptedEntries = []; // populated inside loadEntries()

async function promptUnlock() {
  const metaRef = doc(db, 'users', currentUser.uid, 'keyMeta', 'salt');
  const metaSnap = await getDoc(metaRef);
  let salt;
  const isFirstTime = !metaSnap.exists();

  const tabPassphrase = $('tab-passphrase');
  const tabRecovery = $('tab-recovery');
  const passphraseGroup = $('passphrase-group');
  const recoveryGroup = $('recovery-group');
  const passphraseInput = $('passphrase-input');
  const recoveryInput = $('recovery-input');
  const unlockTabs = $('unlock-tabs');

  let activeMode = 'passphrase';

  if (isFirstTime) {
    salt = randomSaltB64();
    await setDoc(metaRef, { salt, createdAt: Date.now() });
    $('unlock-title').textContent = 'Set a journal passphrase (first time)';
    unlockTabs.classList.add('hidden');
    passphraseGroup.classList.remove('hidden');
    recoveryGroup.classList.add('hidden');
    passphraseInput.required = true;
    recoveryInput.required = false;
  } else {
    salt = metaSnap.data().salt;
    $('unlock-title').textContent = 'Enter your journal passphrase';
    unlockTabs.classList.remove('hidden');
    
    // Reset tabs
    tabPassphrase.classList.add('active');
    tabRecovery.classList.remove('active');
    passphraseGroup.classList.remove('hidden');
    recoveryGroup.classList.add('hidden');
    passphraseInput.required = true;
    recoveryInput.required = false;
    activeMode = 'passphrase';
  }

  tabPassphrase.onclick = () => {
    tabPassphrase.classList.add('active');
    tabRecovery.classList.remove('active');
    passphraseGroup.classList.remove('hidden');
    recoveryGroup.classList.add('hidden');
    passphraseInput.required = true;
    recoveryInput.required = false;
    activeMode = 'passphrase';
  };

  tabRecovery.onclick = () => {
    tabRecovery.classList.add('active');
    tabPassphrase.classList.remove('active');
    recoveryGroup.classList.remove('hidden');
    passphraseGroup.classList.add('hidden');
    recoveryInput.required = true;
    passphraseInput.required = false;
    activeMode = 'recovery';
  };

  $('unlock-modal').classList.remove('hidden');

  $('unlock-form').onsubmit = async (e) => {
    e.preventDefault();
    $('unlock-submit-btn').disabled = true;
    try {
      if (activeMode === 'passphrase') {
        const passphrase = passphraseInput.value;
        vaultKey = await deriveKey(passphrase, salt);

        if (isFirstTime) {
          const recoveryCode = generateRecoveryCode();
          const rawKey = await crypto.subtle.exportKey('raw', vaultKey);
          const wrapped = await wrapKey(rawKey, recoveryCode);
          
          const recoveryRef = doc(db, 'users', currentUser.uid, 'keyMeta', 'recovery');
          await setDoc(recoveryRef, {
            ciphertext: wrapped.ciphertext,
            iv: wrapped.iv,
            salt: wrapped.salt,
            createdAt: Date.now()
          });

          $('unlock-modal').classList.add('hidden');
          $('recovery-code-display').textContent = recoveryCode;
          $('recovery-setup-modal').classList.remove('hidden');

          $('recovery-confirm-btn').onclick = async () => {
            $('recovery-setup-modal').classList.add('hidden');
            passphraseInput.value = '';
            await loadEntries();
          };
        } else {
          $('unlock-modal').classList.add('hidden');
          passphraseInput.value = '';
          await loadEntries();
        }
      } else {
        const recoveryCode = recoveryInput.value.trim().toUpperCase();
        const recoveryRef = doc(db, 'users', currentUser.uid, 'keyMeta', 'recovery');
        const recoverySnap = await getDoc(recoveryRef);

        if (!recoverySnap.exists()) {
          throw new Error('No recovery data found for this account.');
        }

        const rData = recoverySnap.data();
        vaultKey = await unwrapKey(rData.ciphertext, rData.iv, rData.salt, recoveryCode);

        $('unlock-modal').classList.add('hidden');
        recoveryInput.value = '';
        await loadEntries();
      }
    } catch (err) {
      alert('Authentication failed: ' + (err.message.includes('Cipher job failed') ? 'Invalid recovery code or passphrase' : err.message));
    } finally {
      $('unlock-submit-btn').disabled = false;
    }
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
  allDecryptedEntries = [];

  const chainEntries = [];
  for (const docSnap of snap.docs) {
    const d = docSnap.data();
    chainEntries.push({ ciphertext: d.ciphertext, iv: d.iv, prevHash: d.prevHash, hash: d.hash });
    lastHash = d.hash;
    try {
      const plaintext = await decryptText(vaultKey, d.ciphertext, d.iv);
      const parsed = JSON.parse(plaintext); 
      
      const row = document.createElement('div');
      
      if (d.type === 'digest' || parsed.digest) {
        row.className = 'turn turn-digest';
        
        const header = document.createElement('div');
        header.className = 'digest-header';
        header.textContent = 'Weekly Reflection Digest';
        row.appendChild(header);
        
        const body = document.createElement('div');
        body.className = 'digest-body';
        body.textContent = parsed.digest;
        row.appendChild(body);
        
        const meta = document.createElement('div');
        meta.className = 'digest-meta';
        
        const mood = document.createElement('div');
        mood.innerHTML = `<span class="digest-meta-title">Mood Insights:</span> ${parsed.moodInsights}`;
        meta.appendChild(mood);
        
        if (parsed.keyThemes && parsed.keyThemes.length) {
          const themes = document.createElement('div');
          themes.innerHTML = '<span class="digest-meta-title">Key Themes:</span>';
          const badges = document.createElement('div');
          badges.className = 'digest-themes';
          parsed.keyThemes.forEach((t) => {
            const badge = document.createElement('span');
            badge.className = 'digest-theme-badge';
            badge.textContent = t;
            badges.appendChild(badge);
          });
          themes.appendChild(badges);
          meta.appendChild(themes);
        }
        
        if (parsed.continuityNotes) {
          const continuity = document.createElement('div');
          continuity.innerHTML = `<span class="digest-meta-title">Continuity Notes:</span> ${parsed.continuityNotes}`;
          meta.appendChild(continuity);
        }
        
        row.appendChild(meta);
      } else {
        decryptedTurns.push(parsed);
        allDecryptedEntries.push({
          role: parsed.role,
          content: parsed.text,
          timestamp: d.createdAt
        });
        row.className = `turn turn-${parsed.role}`;
        row.textContent = parsed.text;
      }
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

// ---------- Weekly Reflection Digest ----------
$('digest-btn').onclick = () => {
  $('digest-focus-input').value = '';
  $('digest-modal').classList.remove('hidden');
};
$('close-digest').onclick = () => {
  $('digest-modal').classList.add('hidden');
};

$('digest-form').onsubmit = async (e) => {
  e.preventDefault();
  const customFocus = $('digest-focus-input').value.trim();
  const eligibleEntries = allDecryptedEntries.filter(
    (entry) => entry.timestamp >= Date.now() - 7 * 24 * 60 * 60 * 1000
  );

  if (eligibleEntries.length === 0) {
    alert('You need at least one journal entry from the past week to generate a digest.');
    return;
  }

  $('digest-submit-btn').disabled = true;
  $('digest-submit-btn').textContent = 'Generating...';

  try {
    const idToken = await currentUser.getIdToken();
    const res = await fetch(`${GATEWAY_URL}/api/digest`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${idToken}`
      },
      body: JSON.stringify({
        entries: eligibleEntries,
        customFocus
      })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Request failed');

    const digestPayload = JSON.stringify({
      digest: data.digest,
      keyThemes: data.keyThemes,
      moodInsights: data.moodInsights,
      continuityNotes: data.continuityNotes
    });

    const { ciphertext, iv } = await encryptText(vaultKey, digestPayload);
    const hash = await computeEntryHash(lastHash, ciphertext, iv);
    
    const entriesRef = collection(db, 'users', currentUser.uid, 'entries');
    await addDoc(entriesRef, {
      ciphertext,
      iv,
      prevHash: lastHash,
      hash,
      type: 'digest',
      createdAt: Date.now()
    });

    lastHash = hash;
    $('digest-modal').classList.add('hidden');
    await loadEntries();
  } catch (err) {
    alert('Failed to generate weekly digest: ' + err.message);
  } finally {
    $('digest-submit-btn').disabled = false;
    $('digest-submit-btn').textContent = 'Generate';
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
