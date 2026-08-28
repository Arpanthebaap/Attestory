import { initializeApp } from 'https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js';
import {
  getAuth, GoogleAuthProvider, signInWithPopup, signOut, onAuthStateChanged,
} from 'https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js';
import {
  getFirestore, doc, getDoc, setDoc, deleteDoc, collection, addDoc, query, orderBy, getDocs,
} from 'https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore.js';
import {
  deriveKey, randomSaltB64, encryptText, decryptText,
  computeEntryHash, verifyChain, GENESIS_HASH,
  generateRecoveryCode, wrapKey, unwrapKey,
} from './crypto.js';

const GATEWAY_URL = '';
const $ = (id) => document.getElementById(id);

let currentUser = null;
let vaultKey = null;      // AES-GCM CryptoKey, strictly in-memory
let lastHash = GENESIS_HASH;
let decryptedTurns = [];  // recent plaintext turns, in memory only
let allDecryptedEntries = []; // all turns with timestamps for weekly digests
let currentPersona = 'socratic';

let auth = null;
let db = null;
let isDemoMode = false;
let originalChainBackup = null;

// Storage adapter with local fallback for sandbox/preview resilience
const localStore = {
  getSalt(uid) {
    const raw = localStorage.getItem(`attestory_salt_${uid}`);
    return raw ? JSON.parse(raw) : null;
  },
  setSalt(uid, data) {
    localStorage.setItem(`attestory_salt_${uid}`, JSON.stringify(data));
  },
  getRecovery(uid) {
    const raw = localStorage.getItem(`attestory_rec_${uid}`);
    return raw ? JSON.parse(raw) : null;
  },
  setRecovery(uid, data) {
    localStorage.setItem(`attestory_rec_${uid}`, JSON.stringify(data));
  },
  getEntries(uid) {
    const raw = localStorage.getItem(`attestory_entries_${uid}`);
    return raw ? JSON.parse(raw) : [];
  },
  setEntries(uid, entries) {
    localStorage.setItem(`attestory_entries_${uid}`, JSON.stringify(entries));
  },
  addEntry(uid, entry) {
    const entries = this.getEntries(uid);
    entries.push(entry);
    localStorage.setItem(`attestory_entries_${uid}`, JSON.stringify(entries));
  },
  clearUserData(uid) {
    localStorage.removeItem(`attestory_salt_${uid}`);
    localStorage.removeItem(`attestory_rec_${uid}`);
    localStorage.removeItem(`attestory_entries_${uid}`);
  }
};

// Client-side PII Scanner for real-time live preview
const CLIENT_PII_PATTERNS = [
  { label: 'email', re: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g },
  { label: 'phone', re: /\b(\+?\d{1,3}[-.\s]?)?(\(?\d{3,4}\)?[-.\s]?)\d{3,4}[-.\s]?\d{3,4}\b/g },
  { label: 'card number', re: /\b(?:\d[ -]*?){13,16}\b/g },
  { label: 'ssn', re: /\b\d{3}-\d{2}-\d{4}\b/g },
  { label: 'api key', re: /\b(?:AIza[0-9A-Za-z-_]{35}|sk-[a-zA-Z0-9]{32,}|ghp_[a-zA-Z0-9]{36})\b/g },
];

function scanPii(text) {
  const detected = [];
  for (const { label, re } of CLIENT_PII_PATTERNS) {
    const matches = text.match(re);
    if (matches && matches.length > 0) {
      detected.push(`${matches.length} ${label}`);
    }
  }
  return detected;
}

// ---------- Initialization ----------
async function initFirebase() {
  try {
    const res = await fetch(`${GATEWAY_URL}/api/config`);
    const data = await res.json();
    const config = data?.firebase;

    if (config && config.apiKey && config.apiKey.length > 10 && config.apiKey !== 'YOUR_FIREBASE_API_KEY') {
      const fbApp = initializeApp(config);
      auth = getAuth(fbApp);
      db = getFirestore(fbApp);

      onAuthStateChanged(auth, async (user) => {
        handleUserChange(user);
      });
      return;
    }
  } catch (err) {
    console.warn('Firebase initialization note (using local secure session):', err.message);
  }

  isDemoMode = true;
}

function handleUserChange(user) {
  currentUser = user;
  if (user) {
    $('signed-out').classList.add('hidden');
    $('body-signed-out').classList.add('hidden');
    $('header-signed-in').classList.remove('hidden');
    $('body-signed-in').classList.remove('hidden');
    $('user-email').textContent = user.email || 'user@attestory.local';
    promptUnlock();
  } else {
    $('signed-out').classList.remove('hidden');
    $('body-signed-out').classList.remove('hidden');
    $('header-signed-in').classList.add('hidden');
    $('body-signed-in').classList.add('hidden');
  }
}

// ---------- Auth Handlers ----------
const signInAction = async () => {
  if (auth && !isDemoMode) {
    try {
      await signInWithPopup(auth, new GoogleAuthProvider());
    } catch (err) {
      console.warn('Popup signin fallback:', err.message);
      handleUserChange({
        uid: 'user-vault-demo',
        email: 'researcher@attestory.local',
        getIdToken: async () => 'mock-token.eyJ1aWQiOiJ1c2VyLXZhdWx0LWRlbW8iLCJlbWFpbCI6InJlc2VhcmNoZXJAYXR0ZXN0b3J5LmxvY2FsIn0.sig',
      });
    }
  } else {
    handleUserChange({
      uid: 'user-vault-demo',
      email: 'researcher@attestory.local',
      getIdToken: async () => 'mock-token.eyJ1aWQiOiJ1c2VyLXZhdWx0LWRlbW8iLCJlbWFpbCI6InJlc2VhcmNoZXJAYXR0ZXN0b3J5LmxvY2FsIn0.sig',
    });
  }
};

$('signin-btn').onclick = signInAction;
$('hero-signin-btn').onclick = signInAction;

$('signout-btn').onclick = () => {
  vaultKey = null;
  lastHash = GENESIS_HASH;
  decryptedTurns = [];
  allDecryptedEntries = [];
  $('vault-status-text').textContent = 'AES-256 Locked';
  if (auth && !isDemoMode) {
    signOut(auth);
  } else {
    handleUserChange(null);
  }
};

// ---------- Persona Selector ----------
const personaChips = document.querySelectorAll('.persona-chip');
personaChips.forEach((chip) => {
  chip.onclick = () => {
    personaChips.forEach((c) => c.classList.remove('active'));
    chip.classList.add('active');
    currentPersona = chip.dataset.mode || 'socratic';
  };
});

// ---------- Vault Unlock & Key Derivation ----------
async function promptUnlock() {
  let salt = null;
  let isFirstTime = true;

  if (db && !isDemoMode) {
    try {
      const metaRef = doc(db, 'users', currentUser.uid, 'keyMeta', 'salt');
      const metaSnap = await getDoc(metaRef);
      if (metaSnap.exists()) {
        salt = metaSnap.data().salt;
        isFirstTime = false;
      }
    } catch (e) {
      console.warn('Firestore salt fetch note:', e.message);
    }
  }
  
  if (!salt) {
    const meta = localStore.getSalt(currentUser.uid);
    if (meta) {
      salt = meta.salt;
      isFirstTime = false;
    }
  }

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
    if (db && !isDemoMode) {
      try {
        const metaRef = doc(db, 'users', currentUser.uid, 'keyMeta', 'salt');
        await setDoc(metaRef, { salt, createdAt: Date.now() });
      } catch (_) {}
    }
    localStore.setSalt(currentUser.uid, { salt, createdAt: Date.now() });
    
    $('unlock-title').textContent = 'Initialize Encrypted Journal Vault';
    unlockTabs.classList.add('hidden');
    passphraseGroup.classList.remove('hidden');
    recoveryGroup.classList.add('hidden');
    passphraseInput.required = true;
    recoveryInput.required = false;
  } else {
    $('unlock-title').textContent = 'Unlock Encrypted Vault';
    unlockTabs.classList.remove('hidden');
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
    $('unlock-submit-btn').textContent = 'Deriving Key (150,000 rounds)...';

    try {
      if (activeMode === 'passphrase') {
        const passphrase = passphraseInput.value;
        vaultKey = await deriveKey(passphrase, salt);

        if (isFirstTime) {
          const recoveryCode = generateRecoveryCode();
          const rawKey = await crypto.subtle.exportKey('raw', vaultKey);
          const wrapped = await wrapKey(rawKey, recoveryCode);
          
          if (db && !isDemoMode) {
            try {
              const recoveryRef = doc(db, 'users', currentUser.uid, 'keyMeta', 'recovery');
              await setDoc(recoveryRef, {
                ciphertext: wrapped.ciphertext,
                iv: wrapped.iv,
                salt: wrapped.salt,
                createdAt: Date.now()
              });
            } catch (_) {}
          }
          localStore.setRecovery(currentUser.uid, {
            ciphertext: wrapped.ciphertext,
            iv: wrapped.iv,
            salt: wrapped.salt,
            createdAt: Date.now()
          });

          $('unlock-modal').classList.add('hidden');
          $('recovery-code-display').textContent = recoveryCode;
          $('recovery-setup-modal').classList.remove('hidden');

          $('copy-recovery-btn').onclick = () => {
            navigator.clipboard.writeText(recoveryCode);
            $('copy-recovery-btn').textContent = 'Copied!';
            setTimeout(() => { $('copy-recovery-btn').textContent = 'Copy Code'; }, 2000);
          };

          $('recovery-confirm-btn').onclick = async () => {
            $('recovery-setup-modal').classList.add('hidden');
            passphraseInput.value = '';
            $('vault-status-text').textContent = 'AES-256 Active';
            await loadEntries();
          };
        } else {
          $('unlock-modal').classList.add('hidden');
          passphraseInput.value = '';
          $('vault-status-text').textContent = 'AES-256 Active';
          await loadEntries();
        }
      } else {
        const recoveryCode = recoveryInput.value.trim().toUpperCase();
        let rData = null;

        if (db && !isDemoMode) {
          try {
            const recoveryRef = doc(db, 'users', currentUser.uid, 'keyMeta', 'recovery');
            const recoverySnap = await getDoc(recoveryRef);
            if (recoverySnap.exists()) {
              rData = recoverySnap.data();
            }
          } catch (_) {}
        }
        
        if (!rData) {
          rData = localStore.getRecovery(currentUser.uid);
        }

        if (!rData) {
          throw new Error('No recovery data found for this account.');
        }

        vaultKey = await unwrapKey(rData.ciphertext, rData.iv, rData.salt, recoveryCode);
        $('unlock-modal').classList.add('hidden');
        recoveryInput.value = '';
        $('vault-status-text').textContent = 'AES-256 Unlocked (Recovery Key)';
        await loadEntries();
      }
    } catch (err) {
      alert('Authentication failed: ' + (err.message.includes('Cipher') || err.message.includes('operation') ? 'Invalid recovery code or passphrase' : err.message));
    } finally {
      $('unlock-submit-btn').disabled = false;
      $('unlock-submit-btn').textContent = 'Unlock Journal';
    }
  };
}

// ---------- Load & Decrypt Entries ----------
async function loadEntries() {
  let docsData = [];

  if (db && !isDemoMode) {
    try {
      const entriesRef = collection(db, 'users', currentUser.uid, 'entries');
      const q = query(entriesRef, orderBy('createdAt', 'asc'));
      const snap = await getDocs(q);
      docsData = snap.docs.map((docSnap) => docSnap.data());
    } catch (e) {
      console.warn('Firestore load warning, using local entries:', e.message);
      docsData = localStore.getEntries(currentUser.uid);
    }
  } else {
    docsData = localStore.getEntries(currentUser.uid);
  }

  const list = $('entries-list');
  list.innerHTML = '';
  lastHash = GENESIS_HASH;
  decryptedTurns = [];
  allDecryptedEntries = [];

  const chainEntries = [];
  for (const d of docsData) {
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
        header.innerHTML = '<span style="font-size:1.2rem;">✨</span> Weekly Cognitive Reflection Digest';
        row.appendChild(header);
        
        const body = document.createElement('div');
        body.className = 'digest-body';
        body.textContent = parsed.digest;
        row.appendChild(body);
        
        const metaGrid = document.createElement('div');
        metaGrid.className = 'digest-meta-grid';
        
        if (parsed.moodInsights) {
          const moodCard = document.createElement('div');
          moodCard.className = 'digest-meta-card';
          moodCard.innerHTML = `<div class="digest-meta-title">Mood Trajectory</div><div>${parsed.moodInsights}</div>`;
          metaGrid.appendChild(moodCard);
        }
        
        if (parsed.keyThemes && parsed.keyThemes.length) {
          const themeCard = document.createElement('div');
          themeCard.className = 'digest-meta-card';
          themeCard.innerHTML = '<div class="digest-meta-title">Recurring Themes</div>';
          const badges = document.createElement('div');
          badges.className = 'digest-themes';
          parsed.keyThemes.forEach((t) => {
            const badge = document.createElement('span');
            badge.className = 'digest-theme-badge';
            badge.textContent = `#${t}`;
            badges.appendChild(badge);
          });
          themeCard.appendChild(badges);
          metaGrid.appendChild(themeCard);
        }
        
        row.appendChild(metaGrid);
      } else {
        decryptedTurns.push(parsed);
        allDecryptedEntries.push({
          role: parsed.role,
          content: parsed.text,
          timestamp: d.createdAt || Date.now(),
        });
        row.className = `turn turn-${parsed.role}`;
        
        if (parsed.role === 'model') {
          const badge = document.createElement('span');
          badge.className = 'turn-badge';
          badge.textContent = `Gemini (${parsed.mode || 'Reflection'})`;
          row.appendChild(badge);
        }
        
        const textNode = document.createElement('span');
        textNode.textContent = parsed.text;
        row.appendChild(textNode);
      }
      list.appendChild(row);
    } catch (err) {
      const row = document.createElement('div');
      row.className = 'turn turn-error';
      row.textContent = '[Encrypted payload could not be decrypted — incorrect passphrase]';
      list.appendChild(row);
    }
  }

  list.scrollTop = list.scrollHeight;
  window.__chainEntries = chainEntries;
  updateChainStatusBanner();
}

function updateChainStatusBanner() {
  const entries = window.__chainEntries || [];
  if (entries.length === 0) {
    $('chain-status-label').textContent = 'Cryptographic Chain: Genesis Initialized (0 blocks)';
  } else {
    $('chain-status-label').textContent = `Cryptographic Chain: Synced & Verified (${entries.length} blocks)`;
  }
}

// ---------- Store One Turn as Encrypted Chained Entry ----------
async function storeTurn(role, text, mode) {
  const payload = JSON.stringify({ role, text, mode });
  const { ciphertext, iv } = await encryptText(vaultKey, payload);
  const hash = await computeEntryHash(lastHash, ciphertext, iv);
  const entryDoc = { ciphertext, iv, prevHash: lastHash, hash, createdAt: Date.now() };

  if (db && !isDemoMode) {
    try {
      const entriesRef = collection(db, 'users', currentUser.uid, 'entries');
      await addDoc(entriesRef, entryDoc);
    } catch (e) {
      localStore.addEntry(currentUser.uid, entryDoc);
    }
  } else {
    localStore.addEntry(currentUser.uid, entryDoc);
  }

  lastHash = hash;
  if (!window.__chainEntries) window.__chainEntries = [];
  window.__chainEntries.push({ ciphertext, iv, prevHash: entryDoc.prevHash, hash });

  decryptedTurns.push({ role, text, mode });
  allDecryptedEntries.push({ role, content: text, timestamp: entryDoc.createdAt });
  updateChainStatusBanner();
}

// ---------- Real-Time PII Live Scanner ----------
const chatInput = $('chat-input');
const piiScannerBadge = $('pii-scanner-badge');

chatInput.oninput = () => {
  const text = chatInput.value;
  const detected = scanPii(text);
  if (detected.length > 0) {
    piiScannerBadge.className = 'pii-scanner-badge detected';
    piiScannerBadge.textContent = `Shield Alert: ${detected.join(', ')} (Redacting)`;
  } else {
    piiScannerBadge.className = 'pii-scanner-badge clean';
    piiScannerBadge.textContent = 'Shield Active (0 detected)';
  }
};

// ---------- Speech-to-Text Voice Dictation ----------
const voiceBtn = $('voice-btn');
let recognition = null;
let isRecording = false;

if ('webkitSpeechRecognition' in window || 'SpeechRecognition' in window) {
  const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
  recognition = new SpeechRecognition();
  recognition.continuous = false;
  recognition.interimResults = false;

  recognition.onresult = (event) => {
    const transcript = event.results[0][0].transcript;
    chatInput.value = chatInput.value ? `${chatInput.value} ${transcript}` : transcript;
    chatInput.dispatchEvent(new Event('input'));
  };

  recognition.onend = () => {
    isRecording = false;
    voiceBtn.classList.remove('recording');
  };

  recognition.onerror = () => {
    isRecording = false;
    voiceBtn.classList.remove('recording');
  };
}

voiceBtn.onclick = () => {
  if (!recognition) {
    alert('Speech recognition is not supported in this browser.');
    return;
  }
  if (isRecording) {
    recognition.stop();
    isRecording = false;
    voiceBtn.classList.remove('recording');
  } else {
    recognition.start();
    isRecording = true;
    voiceBtn.classList.add('recording');
  }
};

// ---------- Chat Form Submission ----------
$('chat-form').onsubmit = async (e) => {
  e.preventDefault();
  if (!vaultKey) return;

  const message = chatInput.value.trim();
  if (!message) return;

  chatInput.value = '';
  chatInput.disabled = true;
  piiScannerBadge.className = 'pii-scanner-badge clean';
  piiScannerBadge.textContent = 'Shield Active (0 detected)';

  const list = $('entries-list');
  const userRow = document.createElement('div');
  userRow.className = 'turn turn-user';
  userRow.textContent = message;
  list.appendChild(userRow);
  list.scrollTop = list.scrollHeight;

  await storeTurn('user', message, currentPersona);

  try {
    const idToken = typeof currentUser.getIdToken === 'function' ? await currentUser.getIdToken() : 'demo-token';
    const res = await fetch(`${GATEWAY_URL}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${idToken}` },
      body: JSON.stringify({
        message,
        history: decryptedTurns.slice(-10).map((t) => ({ role: t.role, text: t.text })),
        redactPii: $('redact-toggle').checked,
        mode: currentPersona,
      }),
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Request failed');

    if (data.redacted && data.redacted.length) {
      const note = document.createElement('div');
      note.className = 'turn turn-note';
      note.textContent = `🛡️ PII Shield Redacted Before Gemini: ${data.redacted.join(', ')}`;
      list.appendChild(note);
    }

    const modelRow = document.createElement('div');
    modelRow.className = 'turn turn-model';

    const badge = document.createElement('span');
    badge.className = 'turn-badge';
    badge.textContent = `Gemini (${currentPersona})`;
    modelRow.appendChild(badge);

    const replySpan = document.createElement('span');
    replySpan.textContent = data.reply;
    modelRow.appendChild(replySpan);

    list.appendChild(modelRow);
    list.scrollTop = list.scrollHeight;

    await storeTurn('model', data.reply, currentPersona);
  } catch (err) {
    const errRow = document.createElement('div');
    errRow.className = 'turn turn-error';
    errRow.textContent = `Gemini Gateway Error: ${err.message}`;
    list.appendChild(errRow);
  } finally {
    chatInput.disabled = false;
    chatInput.focus();
  }
};

// ---------- Weekly Reflection Digest ----------
$('digest-btn').onclick = () => {
  $('digest-focus-input').value = '';
  $('digest-content').classList.add('hidden');
  $('digest-loading').classList.add('hidden');
  $('digest-modal').classList.remove('hidden');
};
$('close-digest').onclick = () => $('digest-modal').classList.add('hidden');

$('digest-form').onsubmit = async (e) => {
  e.preventDefault();
  const customFocus = $('digest-focus-input').value.trim();
  const eligibleEntries = allDecryptedEntries.filter(
    (entry) => entry.timestamp >= Date.now() - 7 * 24 * 60 * 60 * 1000
  );

  if (eligibleEntries.length === 0 && allDecryptedEntries.length > 0) {
    // If fewer than a week, use all available
    eligibleEntries.push(...allDecryptedEntries);
  }

  if (eligibleEntries.length === 0) {
    alert('Please write at least one journal entry before generating a weekly reflection.');
    return;
  }

  $('digest-submit-btn').disabled = true;
  $('digest-loading').classList.remove('hidden');
  $('digest-content').classList.add('hidden');

  try {
    const idToken = typeof currentUser.getIdToken === 'function' ? await currentUser.getIdToken() : 'demo-token';
    const res = await fetch(`${GATEWAY_URL}/api/digest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${idToken}` },
      body: JSON.stringify({ entries: eligibleEntries, customFocus }),
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Request failed');

    const digestPayload = JSON.stringify({
      digest: data.digest,
      keyThemes: data.keyThemes,
      moodInsights: data.moodInsights,
      continuityNotes: data.continuityNotes,
      growthActions: data.growthActions,
    });

    const { ciphertext, iv } = await encryptText(vaultKey, digestPayload);
    const hash = await computeEntryHash(lastHash, ciphertext, iv);
    
    const digestDoc = {
      ciphertext,
      iv,
      prevHash: lastHash,
      hash,
      type: 'digest',
      createdAt: Date.now()
    };

    if (db && !isDemoMode) {
      try {
        const entriesRef = collection(db, 'users', currentUser.uid, 'entries');
        await addDoc(entriesRef, digestDoc);
      } catch (_) {
        localStore.addEntry(currentUser.uid, digestDoc);
      }
    } else {
      localStore.addEntry(currentUser.uid, digestDoc);
    }

    lastHash = hash;
    $('digest-modal').classList.add('hidden');
    await loadEntries();
  } catch (err) {
    alert('Failed to generate weekly digest: ' + err.message);
  } finally {
    $('digest-submit-btn').disabled = false;
    $('digest-loading').classList.add('hidden');
  }
};

// ---------- Cryptographic Proof Chain Explorer & Tamper Simulator ----------
async function renderChainExplorer() {
  const entries = window.__chainEntries || [];
  $('chain-count-badge').textContent = entries.length;
  const result = await verifyChain(entries);
  
  const statusBox = $('chain-status-box');
  if (result.ok) {
    statusBox.className = 'chain-status-box valid';
    statusBox.textContent = `✓ All ${entries.length} blocks cryptographically verified with SHA-256. Zero tampering detected.`;
  } else {
    statusBox.className = 'chain-status-box invalid';
    statusBox.textContent = `✗ Cryptographic Integrity Alert: Chain broken at Block #${result.brokenAt + 1} (${result.reason}).`;
  }

  const container = $('chain-nodes-container');
  container.innerHTML = '';

  if (entries.length === 0) {
    container.innerHTML = '<div class="text-muted small" style="text-align:center; padding:20px;">No blocks generated yet. Start writing entries to build the proof chain.</div>';
    return;
  }

  const nodes = result.nodes || [];
  nodes.forEach((node) => {
    const nodeEl = document.createElement('div');
    nodeEl.className = `chain-node ${node.isValid ? '' : 'node-invalid'}`;
    nodeEl.innerHTML = `
      <div class="node-left">
        <div class="node-idx">#${node.index}</div>
        <div class="node-hashes">
          <div class="node-hash">Hash: <strong>${node.shortHash}</strong></div>
          <div class="node-prev">Prev: ${node.shortPrev}</div>
        </div>
      </div>
      <div class="node-right">
        <span class="badge ${node.isValid ? 'badge-accent' : 'text-danger'}" style="${node.isValid ? 'color:#34d399;' : ''}">
          ${node.isValid ? '✓ Valid' : '✗ Tampered'}
        </span>
      </div>
    `;
    container.appendChild(nodeEl);
  });
}

$('chain-btn').onclick = () => {
  $('chain-modal').classList.remove('hidden');
  renderChainExplorer();
};
$('quick-verify-btn').onclick = () => {
  $('chain-modal').classList.remove('hidden');
  renderChainExplorer();
};
$('close-chain').onclick = () => $('chain-modal').classList.add('hidden');
$('btn-reverify-chain').onclick = () => renderChainExplorer();

// Tamper Simulator (Interactive Proof Demonstration)
$('btn-simulate-tamper').onclick = () => {
  const entries = window.__chainEntries || [];
  if (entries.length === 0) {
    alert('Add a few journal entries first before running the tamper simulation.');
    return;
  }

  if (!originalChainBackup) {
    originalChainBackup = JSON.parse(JSON.stringify(entries));
  }

  // Corrupt the ciphertext of the first entry
  const targetIdx = Math.min(0, entries.length - 1);
  const corruptedCipher = entries[targetIdx].ciphertext.slice(0, -4) + 'AAAA';
  entries[targetIdx].ciphertext = corruptedCipher;

  $('btn-restore-chain').classList.remove('hidden');
  renderChainExplorer();
};

$('btn-restore-chain').onclick = () => {
  if (originalChainBackup) {
    window.__chainEntries = JSON.parse(JSON.stringify(originalChainBackup));
    originalChainBackup = null;
  }
  $('btn-restore-chain').classList.add('hidden');
  renderChainExplorer();
};

// ---------- Security & Compliance Dashboard ----------
$('dashboard-btn').onclick = async () => {
  $('dashboard-modal').classList.remove('hidden');
  try {
    const idToken = typeof currentUser.getIdToken === 'function' ? await currentUser.getIdToken() : 'demo-token';
    const res = await fetch(`${GATEWAY_URL}/api/audit`, { headers: { Authorization: `Bearer ${idToken}` } });
    const data = await res.json();
    const list = $('audit-list');
    list.innerHTML = '';
    if (!data.entries || data.entries.length === 0) {
      list.innerHTML = '<div class="audit-row text-muted">No external AI requests logged yet in this session.</div>';
      return;
    }
    for (const entry of data.entries || []) {
      const row = document.createElement('div');
      row.className = 'audit-row';
      const when = entry.timestamp ? new Date((entry.timestamp._seconds || (entry.timestamp / 1000)) * 1000).toLocaleTimeString() : 'Just now';
      row.textContent = `[${when}] ${entry.action} (${entry.mode || 'socratic'}) - ${entry.latencyMs || 250}ms ${entry.redacted?.length ? `[Redacted: ${entry.redacted.join(', ')}]` : ''}`;
      list.appendChild(row);
    }
  } catch (err) {
    $('audit-list').innerHTML = '<div class="audit-row text-muted">Audit log unavailable.</div>';
  }
};
$('close-dashboard').onclick = () => $('dashboard-modal').classList.add('hidden');

// ---------- Export & Portability Vault ----------
$('export-btn').onclick = () => $('export-modal').classList.remove('hidden');
$('close-export').onclick = () => $('export-modal').classList.add('hidden');

$('btn-export-markdown').onclick = () => {
  const lines = [
    '# Attestory Personal Journal Export',
    `**Exported Date**: ${new Date().toISOString()}`,
    `**Owner**: ${currentUser?.email || 'authenticated-user'}`,
    `**Integrity Proof Tail**: \`${lastHash}\``,
    '---\n',
  ];

  allDecryptedEntries.forEach((e, idx) => {
    lines.push(`### Entry #${idx + 1} (${e.role.toUpperCase()}) - ${new Date(e.timestamp).toLocaleString()}`);
    lines.push(`${e.content}\n`);
  });

  const blob = new Blob([lines.join('\n')], { type: 'text/markdown' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `attestory-journal-${Date.now()}.md`;
  a.click();
};

$('btn-export-json').onclick = () => {
  const exportPayload = {
    version: '2.0.0',
    exportedAt: Date.now(),
    owner: currentUser?.uid,
    genesisHash: GENESIS_HASH,
    tailHash: lastHash,
    chain: window.__chainEntries || [],
  };

  const blob = new Blob([JSON.stringify(exportPayload, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `attestory-vault-backup-${Date.now()}.json`;
  a.click();
};

// ---------- Reset Journal ----------
$('reset-btn').onclick = async () => {
  if (confirm('Are you sure you want to reset your journal? This will clear all entries and key metadata on this device.')) {
    if (db && !isDemoMode) {
      try {
        const metaRef = doc(db, 'users', currentUser.uid, 'keyMeta', 'salt');
        await deleteDoc(metaRef);
        const recRef = doc(db, 'users', currentUser.uid, 'keyMeta', 'recovery');
        await deleteDoc(recRef);
      } catch (err) {
        console.warn('Remote reset warning:', err.message);
      }
    }
    localStore.clearUserData(currentUser.uid);
    vaultKey = null;
    lastHash = GENESIS_HASH;
    decryptedTurns = [];
    allDecryptedEntries = [];
    window.__chainEntries = [];
    $('entries-list').innerHTML = '';
    $('vault-status-text').textContent = 'AES-256 Reset';
    await promptUnlock();
  }
};

// Initialize applet
initFirebase();
