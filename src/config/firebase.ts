import admin from 'firebase-admin';
import { logger } from '../helpers/logger';

const requiredEnvVars = [
  'FIREBASE_PROJECT_ID',
  'FIREBASE_CLIENT_EMAIL',
  'FIREBASE_PRIVATE_KEY',
];

const missingEnvVars = requiredEnvVars.filter((v) => !process.env[v]);
if (missingEnvVars.length > 0) {
  logger.fatal('startup.missing_env', { vars: missingEnvVars.join(', ') });
  process.exit(1);
}

admin.initializeApp({
  credential: admin.credential.cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    // Render stores \n as literal \\n in env vars - convert back
    privateKey: process.env.FIREBASE_PRIVATE_KEY!.replace(/\\n/g, '\n'),
  }),
});

const db = admin.firestore();
logger.info('startup.firebase_ready', {
  projectId: process.env.FIREBASE_PROJECT_ID,
});

export { admin, db };
