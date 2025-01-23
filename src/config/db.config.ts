import admin from 'firebase-admin';
import fs from 'fs';
import dotenv from 'dotenv';
dotenv.config()

const credentialFirebase = process.env.FIREBASE_CREDENTIALS;
const credentialsPath = process.env.FIREBASE_CREDENTIALS_PATH || '';

const credentials = credentialFirebase ? JSON.parse(credentialFirebase) : JSON.parse(fs.readFileSync(credentialsPath, 'utf8'));
if(!credentials){
    console.error("FIREBASE_CREDENTIALS environment variable is not set.");
    process.exit(1);
}

admin.initializeApp({
    credential: admin.credential.cert(credentials as admin.ServiceAccount),
})

export const db = admin.firestore();
export default admin;
