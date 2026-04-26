"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.hashKey = exports.DEFAULT_LICENSE_POLICY = exports.PAID_LICENSE_PLANS = exports.CURRENT_PAID_LICENSE_PLANS = exports.LICENSE_PLAN_DURATIONS_DAYS = void 0;
exports.isPaidLicensePlan = isPaidLicensePlan;
exports.normalizeLicensePlan = normalizeLicensePlan;
exports.getLicensePlanDurationDays = getLicensePlanDurationDays;
exports.getLicensePublicKeyPem = getLicensePublicKeyPem;
exports.createFreeLicense = createFreeLicense;
exports.signLicenseForUser = signLicenseForUser;
exports.getLicenseForUser = getLicenseForUser;
exports.checkSubscriptionStatus = checkSubscriptionStatus;
const crypto_1 = __importDefault(require("crypto"));
const firebase_1 = require("../config/firebase");
const LICENSE_TOKEN_VERSION = 1;
exports.LICENSE_PLAN_DURATIONS_DAYS = {
    trial_1d: 1,
    trial_2w: 14,
    trial_3m: 90,
    monthly: 30,
    annual: 365,
    biannual: 180,
    lifetime: null,
};
exports.CURRENT_PAID_LICENSE_PLANS = [
    'trial_1d',
    'trial_2w',
    'trial_3m',
    'monthly',
    'annual',
    'biannual',
    'lifetime',
];
const LEGACY_PAID_PLANS = ['pro'];
exports.PAID_LICENSE_PLANS = [
    ...exports.CURRENT_PAID_LICENSE_PLANS,
    ...LEGACY_PAID_PLANS,
];
exports.DEFAULT_LICENSE_POLICY = {
    validationFreshnessHours: 24,
    offlineGraceHours: 48,
    allowExistingTotpWhenStale: true,
    existingTotpGraceHours: 168,
};
const hashKey = (key) => crypto_1.default.createHash('sha256').update(key.trim().toUpperCase()).digest('hex');
exports.hashKey = hashKey;
function isPaidLicensePlan(plan) {
    return (typeof plan === 'string' &&
        exports.PAID_LICENSE_PLANS.includes(plan));
}
function normalizeLicensePlan(plan) {
    if (plan === 'free')
        return 'free';
    return isPaidLicensePlan(plan) ? plan : null;
}
function getLicensePlanDurationDays(plan) {
    if (plan === 'pro')
        return null;
    return exports.LICENSE_PLAN_DURATIONS_DAYS[plan];
}
const generatedDevKeyPair = process.env.NODE_ENV === 'production'
    ? null
    : crypto_1.default.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
function getPrivateKeyPem() {
    const envKey = process.env.LICENSE_SIGNING_PRIVATE_KEY?.replace(/\\n/g, '\n');
    if (envKey)
        return envKey;
    if (generatedDevKeyPair)
        return generatedDevKeyPair.privateKey;
    throw new Error('LICENSE_SIGNING_PRIVATE_KEY is required in production');
}
function getLicensePublicKeyPem() {
    const envPublicKey = process.env.LICENSE_SIGNING_PUBLIC_KEY?.replace(/\\n/g, '\n');
    if (envPublicKey)
        return envPublicKey;
    if (generatedDevKeyPair)
        return generatedDevKeyPair.publicKey;
    return crypto_1.default
        .createPublicKey(getPrivateKeyPem())
        .export({ type: 'spki', format: 'pem' })
        .toString();
}
function base64UrlEncode(input) {
    return Buffer.from(input)
        .toString('base64')
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
}
function signPayload(payload) {
    const header = {
        alg: 'RS256',
        typ: 'JWT',
        kid: process.env.LICENSE_SIGNING_KEY_ID ?? 'passa-license-v1',
    };
    const encodedHeader = base64UrlEncode(JSON.stringify(header));
    const encodedPayload = base64UrlEncode(JSON.stringify(payload));
    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const signer = crypto_1.default.createSign('RSA-SHA256');
    signer.update(signingInput);
    signer.end();
    const signature = signer.sign(getPrivateKeyPem());
    return `${signingInput}.${base64UrlEncode(signature)}`;
}
function createFreeLicense() {
    return { status: 'free', plan: 'free', expires_at: null };
}
function signLicenseForUser(email, license) {
    const now = new Date().toISOString();
    const payload = {
        sub: email,
        status: license?.status ?? 'free',
        plan: normalizeLicensePlan(license?.plan) ?? 'free',
        expires_at: license?.expires_at ?? null,
        issued_at: now,
        validated_at: now,
        token_version: LICENSE_TOKEN_VERSION,
    };
    return {
        ...payload,
        token: signPayload(payload),
    };
}
/**
 * Read subscriptions/{email} and return a license payload for the client.
 * Returns null if no subscription exists.
 */
async function getLicenseForUser(email) {
    const subDoc = await firebase_1.db.collection('subscriptions').doc(email).get();
    if (!subDoc.exists)
        return null;
    const sub = subDoc.data();
    return {
        status: sub['status'],
        plan: normalizeLicensePlan(sub['plan']),
        expires_at: sub['expires_at'] ? sub['expires_at'].toDate().toISOString() : null,
    };
}
/**
 * Check if user has a valid (active) subscription.
 */
async function checkSubscriptionStatus(email) {
    try {
        const userDoc = await firebase_1.db.collection('users').doc(email).get();
        if (userDoc.exists) {
            return userDoc.data()['isSubscribed'] === true;
        }
        return false;
    }
    catch (error) {
        console.error('Subscription check failed:', error.message);
        return false;
    }
}
