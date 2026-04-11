'use strict';
var __importDefault =
  (this && this.__importDefault) ||
  function (mod) {
    return mod && mod.__esModule ? mod : { default: mod };
  };
Object.defineProperty(exports, '__esModule', { value: true });
exports.db = exports.admin = void 0;
const firebase_admin_1 = __importDefault(require('firebase-admin'));
exports.admin = firebase_admin_1.default;
const requiredEnvVars = [
  'FIREBASE_PROJECT_ID',
  'FIREBASE_CLIENT_EMAIL',
  'FIREBASE_PRIVATE_KEY',
];
const missingEnvVars = requiredEnvVars.filter((v) => !process.env[v]);
if (missingEnvVars.length > 0) {
  console.error(
    'FATAL: Missing required environment variables:',
    missingEnvVars.join(', '),
  );
  console.error(
    'Set these in your Render dashboard under Environment > Environment Variables',
  );
  process.exit(1);
}
firebase_admin_1.default.initializeApp({
  credential: firebase_admin_1.default.credential.cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    // Render stores \n as literal \\n in env vars - convert back
    privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
  }),
});
const db = firebase_admin_1.default.firestore();
exports.db = db;
console.log('Firebase Admin initialized successfully', {
  projectId: process.env.FIREBASE_PROJECT_ID,
});
