"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.hashKey = void 0;
exports.getLicenseForUser = getLicenseForUser;
exports.checkSubscriptionStatus = checkSubscriptionStatus;
const crypto_1 = __importDefault(require("crypto"));
const firebase_1 = require("../config/firebase");
const hashKey = (key) => crypto_1.default.createHash('sha256').update(key.trim().toUpperCase()).digest('hex');
exports.hashKey = hashKey;
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
        plan: sub['plan'] ?? null,
        expires_at: sub['expires_at'] ? sub['expires_at'].toDate().toISOString() : null,
    };
}
/**
 * Check if user has a valid (active) subscription.
 */
async function checkSubscriptionStatus(email) {
    try {
        if (process.env.NODE_ENV === 'development')
            return true;
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
