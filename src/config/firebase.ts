import admin from 'firebase-admin';
import { getRequiredEnv } from './env';
import { logger } from '../helpers/logger';

const projectId = getRequiredEnv('FIREBASE_PROJECT_ID');
const clientEmail = getRequiredEnv('FIREBASE_CLIENT_EMAIL');
const privateKey = getRequiredEnv('FIREBASE_PRIVATE_KEY').replace(/\\n/g, '\n');

admin.initializeApp({
  credential: admin.credential.cert({
    projectId,
    clientEmail,
    // Render stores \n as literal \\n in env vars - convert back
    privateKey,
  }),
});

const db = admin.firestore();
logger.info('startup.firebase_ready', {
  projectId,
});

export { admin, db };
