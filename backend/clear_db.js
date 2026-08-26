const admin = require('firebase-admin');

admin.initializeApp({
  projectId: 'attestory-539601'
});

const email = 'arpanghosh984@gmail.com';
const db = admin.firestore();

async function clear() {
  try {
    console.log('Looking up user with email:', email);
    const userRecord = await admin.auth().getUserByEmail(email);
    const uid = userRecord.uid;
    console.log('Found user UID:', uid);
    
    const batch = db.batch();
    
    console.log('Deleting entries...');
    const entriesRef = db.collection('users').doc(uid).collection('entries');
    const entriesSnap = await entriesRef.get();
    entriesSnap.forEach(doc => {
      batch.delete(doc.ref);
    });
    
    console.log('Deleting audit logs...');
    const auditRef = db.collection('users').doc(uid).collection('auditLog');
    const auditSnap = await auditRef.get();
    auditSnap.forEach(doc => {
      batch.delete(doc.ref);
    });
    
    console.log('Deleting key metadata...');
    const metaRef = db.collection('users').doc(uid).collection('keyMeta').doc('salt');
    batch.delete(metaRef);
    
    await batch.commit();
    console.log('Successfully cleared database for user!');
  } catch (err) {
    console.error('Clear failed:', err);
  }
}

clear();
