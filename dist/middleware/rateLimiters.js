"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.analyticsLimiter = exports.licenseLimiter = exports.generalLimiter = exports.oauthRelayLimiter = exports.tokenLimiter = exports.kdfLimiter = exports.registerLimiter = exports.loginLimiter = void 0;
const express_rate_limit_1 = __importDefault(require("express-rate-limit"));
// In the test environment all limiters are skipped so tests never hit 429.
const skipInTest = () => process.env.NODE_ENV === 'test';
// Login: 10 attempts per 15 min per IP. Brute-force at the transport level.
// The per-account lockout inside the handler is a second, independent layer.
exports.loginLimiter = (0, express_rate_limit_1.default)({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: {
        error: 'Too many login attempts. Please try again in 15 minutes.',
    },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true,
    skip: skipInTest,
});
// Registration: 20 new accounts per hour per IP.
exports.registerLimiter = (0, express_rate_limit_1.default)({
    windowMs: 60 * 60 * 1000,
    max: 20,
    message: { error: 'Too many registration attempts. Please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
    skip: skipInTest,
});
// KDF params: 20 lookups per 15 min per IP (used just before login).
exports.kdfLimiter = (0, express_rate_limit_1.default)({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: { error: 'Too many requests. Please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
    skip: skipInTest,
});
// Token exchange / refresh: 20 per 15 min per IP.
exports.tokenLimiter = (0, express_rate_limit_1.default)({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: { error: 'Too many token requests. Please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
    skip: skipInTest,
});
// OAuth relay polling: 60 per 15 min per IP (extension polls for the code).
exports.oauthRelayLimiter = (0, express_rate_limit_1.default)({
    windowMs: 15 * 60 * 1000,
    max: 60,
    message: { error: 'Too many requests. Please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
    skip: skipInTest,
});
// General catch-all: 100 per 15 min per IP for any other routes.
exports.generalLimiter = (0, express_rate_limit_1.default)({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    skip: skipInTest,
});
// License activation: 5 attempts per hour per IP - prevents brute-forcing keys.
exports.licenseLimiter = (0, express_rate_limit_1.default)({
    windowMs: 60 * 60 * 1000,
    max: 5,
    message: { error: 'Too many activation attempts. Please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
    skip: skipInTest,
});
// Analytics: 60 events per 15 min per IP.
exports.analyticsLimiter = (0, express_rate_limit_1.default)({
    windowMs: 15 * 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
    skip: skipInTest,
});
