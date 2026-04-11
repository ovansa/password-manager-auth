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
const router = (0, express_1.Router)();
// Route: Register new user
router.post('/register', rateLimiters_1.registerLimiter, csrf_1.csrfProtection, async (req, res) => {
    const requestTimestamp = (0, email_1.getCurrentTimestamp)();
    console.log('User registration attempt', { timestamp: requestTimestamp, ip: req.ip });
    try {
        const { email, passwordHash, kdfIterations, kdfType, licenseKey } = req.body;
        if (!email || !passwordHash || !kdfIterations || !kdfType || !licenseKey) {
            res.status(400).json({ success: false, error: 'Missing required fields' });
            return;
        }
        const sanitizedEmail = (0, email_1.sanitizeEmail)(email);
        if (!(0, email_1.validateEmail)(sanitizedEmail)) {
            res.status(400).json({ success: false, error: 'Invalid email format' });
            return;
        }
        if (kdfIterations < 100000 || kdfIterations > 2000000) {
            res.status(400).json({ success: false, error: 'Invalid KDF iterations' });
            return;
        }
        const userRef = firebase_1.db.collection('users').doc(sanitizedEmail);
        const userDoc = await userRef.get();
        if (userDoc.exists) {
            console.log('Registration declined - account exists', {
                timestamp: (0, email_1.getCurrentTimestamp)(),
                email: sanitizedEmail,
            });
            res.status(400).json({ success: false, error: 'Registration unsuccessful' });
            return;
        }
        const keyHash = (0, license_1.hashKey)(licenseKey);
        const keyDoc = await firebase_1.db.collection('license_keys').doc(keyHash).get();
        if (!keyDoc.exists || keyDoc.data()['revoked']) {
            res.status(400).json({ success: false, error: 'Invalid license key' });
            return;
        }
        const keyData = keyDoc.data();
        if (keyData['use_count'] >= keyData['max_uses'] && keyData['activated_by'] !== sanitizedEmail) {
            res.status(400).json({ success: false, error: 'License key has already been used' });
            return;
        }
        const serverHash = await bcrypt_1.default.hash(passwordHash, 12);
        const userData = {
            email: sanitizedEmail,
            authHash: serverHash,
            kdfIterations: parseInt(String(kdfIterations)),
            kdfType,
            isSubscribed: true,
            createdAt: new Date(),
            lastLogin: null,
            isActive: true,
            loginAttempts: 0,
            lockedUntil: null,
        };
        await userRef.set(userData);
        let expires_at = null;
        if (keyData['duration_days']) {
            expires_at = new Date(Date.now() + keyData['duration_days'] * 24 * 60 * 60 * 1000);
        }
        const batch = firebase_1.db.batch();
        batch.update(firebase_1.db.collection('license_keys').doc(keyHash), {
            activated_by: sanitizedEmail,
            activated_at: firebase_1.admin.firestore.FieldValue.serverTimestamp(),
            use_count: firebase_1.admin.firestore.FieldValue.increment(1),
        });
        batch.set(firebase_1.db.collection('subscriptions').doc(sanitizedEmail), {
            status: 'active',
            plan: keyData['plan'],
            expires_at: expires_at ? firebase_1.admin.firestore.Timestamp.fromDate(expires_at) : null,
            activated_at: firebase_1.admin.firestore.FieldValue.serverTimestamp(),
            renewed_at: null,
            key_hash: keyHash,
        });
        batch.set(firebase_1.db.collection('license_activations').doc(), {
            email: sanitizedEmail,
            key_hash: keyHash,
            action: 'activated',
            plan: keyData['plan'],
            expires_at: expires_at ? firebase_1.admin.firestore.Timestamp.fromDate(expires_at) : null,
            timestamp: firebase_1.admin.firestore.FieldValue.serverTimestamp(),
            ip: req.ip,
        });
        await batch.commit();
        console.log('User registered successfully', {
            timestamp: (0, email_1.getCurrentTimestamp)(),
            email: sanitizedEmail,
            duration: `${Date.now() - new Date(requestTimestamp).getTime()}ms`,
        });
        res.status(axios_1.HttpStatusCode.Created).json({ success: true, message: 'User registered' });
    }
    catch (error) {
        console.error('Registration error:', {
            timestamp: (0, email_1.getCurrentTimestamp)(),
            error: error.message,
            duration: `${Date.now() - new Date(requestTimestamp).getTime()}ms`,
        });
        res.status(500).json({ success: false, error: 'Registration failed' });
    }
});
// Route: User login
router.post('/login', rateLimiters_1.loginLimiter, csrf_1.csrfProtection, async (req, res) => {
    const requestTimestamp = (0, email_1.getCurrentTimestamp)();
    console.log('Login attempt', { timestamp: requestTimestamp, ip: req.ip });
    try {
        const { email, passwordHash } = req.body;
        if (!email || !passwordHash) {
            res.status(400).json({ success: false, error: 'Missing credentials' });
            return;
        }
        const sanitizedEmail = (0, email_1.sanitizeEmail)(email);
        const userRef = firebase_1.db.collection('users').doc(sanitizedEmail);
        const userDoc = await userRef.get();
        if (!userDoc.exists) {
            await bcrypt_1.default.hash('dummy_password', 12); // consistent timing
            res.status(401).json({ success: false, error: 'Invalid credentials' });
            return;
        }
        const user = userDoc.data();
        if (user['lockedUntil'] && new Date() < user['lockedUntil'].toDate()) {
            res.status(423).json({ success: false, error: 'Account temporarily locked' });
            return;
        }
        const isValidPassword = await bcrypt_1.default.compare(passwordHash, user['authHash']);
        if (!isValidPassword) {
            const attempts = (user['loginAttempts'] ?? 0) + 1;
            const updates = { loginAttempts: attempts };
            if (attempts >= 5) {
                updates['lockedUntil'] = new Date(Date.now() + 30 * 60 * 1000);
            }
            await userRef.update(updates);
            res.status(401).json({ success: false, error: 'Invalid credentials' });
            return;
        }
        await userRef.update({ loginAttempts: 0, lockedUntil: null, lastLogin: new Date() });
        console.log('Successful login', {
            timestamp: (0, email_1.getCurrentTimestamp)(),
            email: sanitizedEmail,
            duration: `${Date.now() - new Date(requestTimestamp).getTime()}ms`,
        });
        const license = await (0, license_1.getLicenseForUser)(sanitizedEmail);
        if (license?.expires_at && new Date(license.expires_at) < new Date()) {
            await firebase_1.db.collection('subscriptions').doc(sanitizedEmail).update({ status: 'expired' });
            license.status = 'expired';
        }
        res.json({
            success: true,
            user: {
                email: user['email'],
                kdfIterations: user['kdfIterations'],
                kdfType: user['kdfType'],
            },
            license: license ?? { status: 'none', plan: null, expires_at: null },
        });
    }
    catch (error) {
        console.error('Login error:', {
            timestamp: (0, email_1.getCurrentTimestamp)(),
            error: error.message,
            duration: `${Date.now() - new Date(requestTimestamp).getTime()}ms`,
        });
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
            res.json({ iterations: 310000, type: 'pbkdf2-sha256' });
            return;
        }
        const user = userDoc.data();
        res.json({ iterations: user['kdfIterations'], type: user['kdfType'] });
    }
    catch (error) {
        const err = error;
        console.error('KDF params error:', { message: err.message, code: err.code });
        res.status(500).json({ error: 'Failed to get parameters' });
    }
});
// Route: Refresh access token
router.post('/refresh', rateLimiters_1.tokenLimiter, async (req, res) => {
    const requestTimestamp = (0, email_1.getCurrentTimestamp)();
    console.log('Received refresh token request', { timestamp: requestTimestamp });
    try {
        const { refresh_token } = req.body;
        const response = await axios_1.default.post('https://oauth2.googleapis.com/token', {
            refresh_token,
            client_id: process.env.GOOGLE_CLIENT_ID,
            client_secret: process.env.GOOGLE_CLIENT_SECRET,
            grant_type: 'refresh_token',
        });
        const responseTimestamp = (0, email_1.getCurrentTimestamp)();
        console.log('Successfully refreshed access token', {
            timestamp: responseTimestamp,
            duration: `${new Date(responseTimestamp).getTime() - new Date(requestTimestamp).getTime()}ms`,
        });
        res.json({
            access_token: response.data.access_token,
            expires_in: response.data.expires_in,
            timestamp: responseTimestamp,
        });
    }
    catch (error) {
        const errorTimestamp = (0, email_1.getCurrentTimestamp)();
        const err = error;
        console.error('Refresh error:', {
            timestamp: errorTimestamp,
            duration: `${new Date(errorTimestamp).getTime() - new Date(requestTimestamp).getTime()}ms`,
            response: err.response?.data,
            error: err.message,
        });
        res.status(400).json({ error: 'Token refresh failed', timestamp: errorTimestamp });
    }
});
exports.default = router;
