"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.db = exports.admin = void 0;
const firebase_admin_1 = __importDefault(require("firebase-admin"));
exports.admin = firebase_admin_1.default;
const env_1 = require("./env");
const logger_1 = require("../helpers/logger");
const projectId = (0, env_1.getRequiredEnv)('FIREBASE_PROJECT_ID');
const clientEmail = (0, env_1.getRequiredEnv)('FIREBASE_CLIENT_EMAIL');
const privateKey = (0, env_1.getRequiredEnv)('FIREBASE_PRIVATE_KEY').replace(/\\n/g, '\n');
firebase_admin_1.default.initializeApp({
    credential: firebase_admin_1.default.credential.cert({
        projectId,
        clientEmail,
        // Render stores \n as literal \\n in env vars - convert back
        privateKey,
    }),
});
const db = firebase_admin_1.default.firestore();
exports.db = db;
logger_1.logger.info('startup.firebase_ready', {
    projectId,
});
