"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const bcrypt_1 = __importDefault(require("bcrypt"));
const axios_1 = __importStar(require("axios"));
const firebase_1 = require("../config/firebase");
const csrf_1 = require("../middleware/csrf");
const rateLimiters_1 = require("../middleware/rateLimiters");
const email_1 = require("../helpers/email");
const license_1 = require("../helpers/license");
const logger_1 = require("../helpers/logger");
const router = (0, express_1.Router)();
// Route: Register new user
router.post('/register', rateLimiters_1.registerLimiter, csrf_1.csrfProtection, async (req, res) => {
    const startMs = Date.now();
    try {
        const { email, passwordHash, kdfIterations, kdfType, licenseKey } = req.body;
        if (!email || !passwordHash || !kdfIterations || !kdfType) {
            logger_1.logger.warn('register.missing_fields', { ip: req.ip });
            res.status(400).json({ success: false, error: 'Missing required fields' });
            return;
        }
        const sanitizedEmail = (0, email_1.sanitizeEmail)(email);
        if (!(0, email_1.validateEmail)(sanitizedEmail)) {
            logger_1.logger.warn('register.invalid_email', { ip: req.ip });
            res.status(400).json({ success: false, error: 'Invalid email format' });
            return;
        }
        if (kdfIterations < 600000 || kdfIterations > 2000000) {
            logger_1.logger.warn('register.invalid_kdf_iterations', { email: sanitizedEmail, kdfIterations });
            res.status(400).json({ success: false, error: 'Invalid KDF iterations' });
            return;
        }
        const VALID_KDF_TYPES = ['pbkdf2-sha256', 'pbkdf2-sha512', 'argon2id'];
        if (!VALID_KDF_TYPES.includes(kdfType)) {
            logger_1.logger.warn('register.invalid_kdf_type', { email: sanitizedEmail, kdfType });
            res.status(400).json({ success: false, error: 'Invalid KDF type' });
            return;
        }
        const userRef = firebase_1.db.collection('users').doc(sanitizedEmail);
        const userDoc = await userRef.get();
        if (userDoc.exists) {
            logger_1.logger.warn('register.email_exists', { email: sanitizedEmail });
            res.status(400).json({ success: false, error: 'Registration unsuccessful' });
            return;
        }
        const trimmedLicenseKey = licenseKey?.trim();
        let keyHash = null;
        let keyData = null;
        let keyPlan = null;
        if (trimmedLicenseKey) {
            keyHash = (0, license_1.hashKey)(trimmedLicenseKey);
            const keyDoc = await firebase_1.db.collection('license_keys').doc(keyHash).get();
            if (!keyDoc.exists || keyDoc.data()['revoked']) {
                logger_1.logger.warn('register.invalid_license', { email: sanitizedEmail });
                res.status(400).json({ success: false, error: 'Invalid license key' });
                return;
            }
            keyData = keyDoc.data();
            if (!(0, license_1.isPaidLicensePlan)(keyData['plan'])) {
                logger_1.logger.warn('register.invalid_license_plan', { email: sanitizedEmail, plan: keyData['plan'] });
                res.status(400).json({ success: false, error: 'Invalid license key' });
                return;
            }
            keyPlan = keyData['plan'];
            if (Number(keyData['use_count'] ?? 0) >= Number(keyData['max_uses'] ?? 1) &&
                keyData['activated_by'] !== sanitizedEmail) {
                logger_1.logger.warn('register.license_exhausted', { email: sanitizedEmail });
                res.status(400).json({ success: false, error: 'License key has already been used' });
                return;
            }
        }
        const serverHash = await bcrypt_1.default.hash(passwordHash, 12);
        const userData = {
            email: sanitizedEmail,
            authHash: serverHash,
            kdfIterations: parseInt(String(kdfIterations)),
            kdfType,
            isSubscribed: !!keyData,
            createdAt: new Date(),
            lastLogin: null,
            isActive: true,
            loginAttempts: 0,
            lockedUntil: null,
        };
        await userRef.set(userData);
        let license = (0, license_1.createFreeLicense)();
        if (keyData && keyHash && keyPlan) {
            let expires_at = null;
            const durationDays = keyData['duration_days'] === undefined
                ? (0, license_1.getLicensePlanDurationDays)(keyPlan)
                : typeof keyData['duration_days'] === 'number'
                    ? keyData['duration_days']
                    : null;
            if (durationDays) {
                expires_at = new Date(durationDays * 24 * 60 * 60 * 1000 + Date.now());
            }
            const batch = firebase_1.db.batch();
            batch.update(firebase_1.db.collection('license_keys').doc(keyHash), {
                activated_by: sanitizedEmail,
                activated_at: firebase_1.admin.firestore.FieldValue.serverTimestamp(),
                use_count: firebase_1.admin.firestore.FieldValue.increment(1),
            });
            batch.set(firebase_1.db.collection('subscriptions').doc(sanitizedEmail), {
                status: 'active',
                plan: keyPlan,
                expires_at: expires_at ? firebase_1.admin.firestore.Timestamp.fromDate(expires_at) : null,
                activated_at: firebase_1.admin.firestore.FieldValue.serverTimestamp(),
                renewed_at: null,
                key_hash: keyHash,
            });
            batch.set(firebase_1.db.collection('license_activations').doc(), {
                email: sanitizedEmail,
                key_hash: keyHash,
                action: 'activated',
                plan: keyPlan,
                expires_at: expires_at ? firebase_1.admin.firestore.Timestamp.fromDate(expires_at) : null,
                timestamp: firebase_1.admin.firestore.FieldValue.serverTimestamp(),
                ip: req.ip,
            });
            await batch.commit();
            license = {
                status: 'active',
                plan: keyPlan,
                expires_at: expires_at ? expires_at.toISOString() : null,
            };
        }
        logger_1.logger.info('register.success', {
            email: sanitizedEmail,
            plan: license.plan,
            durationMs: Date.now() - startMs,
        });
        res.status(axios_1.HttpStatusCode.Created).json({
            success: true,
            message: 'User registered',
            license: (0, license_1.signLicenseForUser)(sanitizedEmail, license),
        });
    }
    catch (error) {
        logger_1.logger.error('register.error', error, { durationMs: Date.now() - startMs });
        res.status(500).json({ success: false, error: 'Registration failed' });
    }
});
// Route: User login
router.post('/login', rateLimiters_1.loginLimiter, csrf_1.csrfProtection, async (req, res) => {
    const startMs = Date.now();
    try {
        const { email, passwordHash } = req.body;
        if (!email || !passwordHash) {
            logger_1.logger.warn('login.missing_credentials', { ip: req.ip });
            res.status(400).json({ success: false, error: 'Missing credentials' });
            return;
        }
        const sanitizedEmail = (0, email_1.sanitizeEmail)(email);
        const userRef = firebase_1.db.collection('users').doc(sanitizedEmail);
        const userDoc = await userRef.get();
        if (!userDoc.exists) {
            await bcrypt_1.default.hash('dummy_password', 12); // consistent timing
            logger_1.logger.warn('login.failed', { ip: req.ip });
            res.status(401).json({ success: false, error: 'Invalid credentials' });
            return;
        }
        const user = userDoc.data();
        if (user['lockedUntil'] && new Date() < user['lockedUntil'].toDate()) {
            logger_1.logger.warn('login.account_locked', {
                email: sanitizedEmail,
                lockedUntil: user['lockedUntil'].toDate().toISOString(),
            });
            res.status(423).json({ success: false, error: 'Account temporarily locked' });
            return;
        }
        const isValidPassword = await bcrypt_1.default.compare(passwordHash, user['authHash']);
        if (!isValidPassword) {
            const attempts = (user['loginAttempts'] ?? 0) + 1;
            const updates = { loginAttempts: attempts };
            if (attempts >= 5) {
                const lockedUntil = new Date(Date.now() + 30 * 60 * 1000);
                updates['lockedUntil'] = lockedUntil;
                logger_1.logger.warn('login.account_now_locked', {
                    email: sanitizedEmail,
                    attempts,
                    lockedUntil: lockedUntil.toISOString(),
                });
            }
            else {
                logger_1.logger.warn('login.failed', { ip: req.ip, attempts });
            }
            await userRef.update(updates);
            res.status(401).json({ success: false, error: 'Invalid credentials' });
            return;
        }
        await userRef.update({ loginAttempts: 0, lockedUntil: null, lastLogin: new Date() });
        logger_1.logger.info('login.success', { email: sanitizedEmail, durationMs: Date.now() - startMs });
        const license = await (0, license_1.getLicenseForUser)(sanitizedEmail);
        if (license?.expires_at && new Date(license.expires_at) < new Date()) {
            await firebase_1.db.collection('subscriptions').doc(sanitizedEmail).update({ status: 'expired' });
            license.status = 'expired';
            logger_1.logger.info('login.license_expired', { email: sanitizedEmail });
        }
        res.json({
            success: true,
            user: {
                email: user['email'],
                kdfIterations: user['kdfIterations'],
                kdfType: user['kdfType'],
            },
            license: (0, license_1.signLicenseForUser)(sanitizedEmail, license ?? (0, license_1.createFreeLicense)()),
        });
    }
    catch (error) {
        logger_1.logger.error('login.error', error, { durationMs: Date.now() - startMs });
        res.status(500).json({ success: false, error: 'Login failed' });
    }
});
// Route: Get KDF parameters for a user
router.get('/kdf-params', rateLimiters_1.kdfLimiter, async (req, res) => {
    try {
        const { email } = req.query;
        if (!email) {
            res.status(400).json({ error: 'Email required' });
            return;
        }
        const sanitizedEmail = (0, email_1.sanitizeEmail)(email);
        if (!(0, email_1.validateEmail)(sanitizedEmail)) {
            res.status(400).json({ error: 'Invalid email format' });
            return;
        }
        const userDoc = await firebase_1.db.collection('users').doc(sanitizedEmail).get();
        if (!userDoc.exists) {
            // Return defaults to prevent user enumeration
            res.json({ iterations: 600000, type: 'pbkdf2-sha256' });
            return;
        }
        const user = userDoc.data();
        res.json({ iterations: user['kdfIterations'], type: user['kdfType'] });
    }
    catch (error) {
        logger_1.logger.error('kdf_params.error', error);
        res.status(500).json({ error: 'Failed to get parameters' });
    }
});
// Route: Refresh access token
router.post('/refresh', rateLimiters_1.tokenLimiter, async (req, res) => {
    const startMs = Date.now();
    try {
        const { refresh_token } = req.body;
        const response = await axios_1.default.post('https://oauth2.googleapis.com/token', {
            refresh_token,
            client_id: process.env.GOOGLE_CLIENT_ID,
            client_secret: process.env.GOOGLE_CLIENT_SECRET,
            grant_type: 'refresh_token',
        });
        logger_1.logger.info('token.refresh_success', { durationMs: Date.now() - startMs });
        res.json({
            access_token: response.data.access_token,
            expires_in: response.data.expires_in,
            timestamp: (0, email_1.getCurrentTimestamp)(),
        });
    }
    catch (error) {
        logger_1.logger.error('token.refresh_error', error, { durationMs: Date.now() - startMs });
        res.status(400).json({ error: 'Token refresh failed', timestamp: (0, email_1.getCurrentTimestamp)() });
    }
});
exports.default = router;
