"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const firebase_1 = require("../config/firebase");
const rateLimiters_1 = require("../middleware/rateLimiters");
const email_1 = require("../helpers/email");
const logger_1 = require("../helpers/logger");
const router = (0, express_1.Router)();
router.post('/', rateLimiters_1.generalLimiter, async (req, res) => {
    try {
        const email = (0, email_1.sanitizeEmail)(String(req.body?.email ?? ''));
        if (!(0, email_1.validateEmail)(email)) {
            res.status(400).json({ error: 'Please enter a valid email address.' });
            return;
        }
        await firebase_1.db.collection('waitlist').doc(email).set({
            email,
            source: req.body?.source ?? 'website',
            updated_at: firebase_1.admin.firestore.FieldValue.serverTimestamp(),
            created_at: firebase_1.admin.firestore.FieldValue.serverTimestamp(),
        }, { merge: true });
        logger_1.logger.info('waitlist.signup', { email });
        res.status(201).json({
            message: "You're on the list! We'll send details for the 3-month Pro launch offer.",
        });
    }
    catch (error) {
        logger_1.logger.error('waitlist.error', error);
        res.status(500).json({ error: 'Something went wrong. Please try again.' });
    }
});
exports.default = router;
