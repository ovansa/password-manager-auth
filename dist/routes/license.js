"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const firebase_1 = require("../config/firebase");
const csrf_1 = require("../middleware/csrf");
const rateLimiters_1 = require("../middleware/rateLimiters");
const email_1 = require("../helpers/email");
const license_1 = require("../helpers/license");
const logger_1 = require("../helpers/logger");
const router = (0, express_1.Router)();
// Route: Activate a license key against a user account
router.post('/activate', rateLimiters_1.licenseLimiter, csrf_1.csrfProtection, async (req, res) => {
    try {
        const { email, key } = req.body;
        if (!email || !key) {
            res.status(400).json({ success: false, error: 'Missing email or key' });
            return;
        }
        const sanitizedEmail = (0, email_1.sanitizeEmail)(email);
        const keyHash = (0, license_1.hashKey)(key);
        const keyRef = firebase_1.db.collection('license_keys').doc(keyHash);
        // Run in a transaction so concurrent activations can't exceed max_uses
        const result = await firebase_1.db.runTransaction(async (tx) => {
            const keyDoc = await tx.get(keyRef);
            if (!keyDoc.exists)
                return { success: false, error: 'Invalid license key' };
            const keyData = keyDoc.data();
            if (!(0, license_1.isPaidLicensePlan)(keyData['plan'])) {
                return { success: false, error: 'Invalid license key' };
            }
            const keyPlan = keyData['plan'];
            if (keyData['revoked']) {
                return { success: false, error: 'This license key has been revoked' };
            }
            if (keyData['use_count'] >= keyData['max_uses']) {
                if (keyData['activated_by'] !== sanitizedEmail) {
                    return { success: false, error: 'This license key has already been used' };
                }
            }
            let expires_at = null;
            const durationDays = keyData['duration_days'] === undefined
                ? (0, license_1.getLicensePlanDurationDays)(keyPlan)
                : typeof keyData['duration_days'] === 'number'
                    ? keyData['duration_days']
                    : null;
            if (durationDays) {
                expires_at = new Date(Date.now() + durationDays * 24 * 60 * 60 * 1000);
            }
            const isReactivation = keyData['activated_by'] === sanitizedEmail;
            tx.update(keyRef, {
                activated_by: sanitizedEmail,
                activated_at: firebase_1.admin.firestore.FieldValue.serverTimestamp(),
                use_count: isReactivation
                    ? keyData['use_count']
                    : firebase_1.admin.firestore.FieldValue.increment(1),
            });
            const subRef = firebase_1.db.collection('subscriptions').doc(sanitizedEmail);
            tx.set(subRef, {
                status: 'active',
                plan: keyPlan,
                expires_at: expires_at ? firebase_1.admin.firestore.Timestamp.fromDate(expires_at) : null,
                activated_at: firebase_1.admin.firestore.FieldValue.serverTimestamp(),
                renewed_at: isReactivation ? firebase_1.admin.firestore.FieldValue.serverTimestamp() : null,
                key_hash: keyHash,
            });
            const logRef = firebase_1.db.collection('license_activations').doc();
            tx.set(logRef, {
                email: sanitizedEmail,
                key_hash: keyHash,
                action: isReactivation ? 'renewed' : 'activated',
                plan: keyPlan,
                expires_at: expires_at ? firebase_1.admin.firestore.Timestamp.fromDate(expires_at) : null,
                timestamp: firebase_1.admin.firestore.FieldValue.serverTimestamp(),
                ip: req.ip,
            });
            return {
                success: true,
                plan: keyPlan,
                expires_at: expires_at ? expires_at.toISOString() : null,
            };
        });
        if (!result.success) {
            logger_1.logger.warn('license.activate_rejected', { email: sanitizedEmail, reason: result.error });
            res.status(400).json(result);
            return;
        }
        logger_1.logger.info('license.activated', { email: sanitizedEmail, plan: result.plan });
        res.json({
            ...result,
            license: (0, license_1.signLicenseForUser)(sanitizedEmail, {
                status: 'active',
                plan: result.plan ?? null,
                expires_at: result.expires_at ?? null,
            }),
        });
    }
    catch (error) {
        logger_1.logger.error('license.activate_error', error);
        res.status(500).json({ success: false, error: 'Activation failed' });
    }
});
// Route: Revalidate current entitlement and return a freshly signed payload
router.post('/validate', rateLimiters_1.licenseLimiter, csrf_1.csrfProtection, async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            res.status(400).json({ success: false, error: 'Missing email' });
            return;
        }
        const sanitizedEmail = (0, email_1.sanitizeEmail)(email);
        const license = await (0, license_1.getLicenseForUser)(sanitizedEmail);
        if (license?.expires_at && new Date(license.expires_at) < new Date()) {
            await firebase_1.db.collection('subscriptions').doc(sanitizedEmail).update({ status: 'expired' });
            license.status = 'expired';
        }
        res.json({
            success: true,
            license: (0, license_1.signLicenseForUser)(sanitizedEmail, license ?? (0, license_1.createFreeLicense)()),
        });
    }
    catch (error) {
        logger_1.logger.error('license.validate_error', error);
        res.status(500).json({ success: false, error: 'Validation failed' });
    }
});
// Route: Check subscription eligibility
router.post('/check-eligibility', rateLimiters_1.licenseLimiter, csrf_1.csrfProtection, async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            res.status(400).json({ eligible: false });
            return;
        }
        const sanitizedEmail = (0, email_1.sanitizeEmail)(email);
        const hasSubscription = await (0, license_1.checkSubscriptionStatus)(sanitizedEmail);
        res.json({ eligible: hasSubscription });
    }
    catch (error) {
        logger_1.logger.error('subscription.check_error', error);
        res.status(500).json({ eligible: false });
    }
});
exports.default = router;
