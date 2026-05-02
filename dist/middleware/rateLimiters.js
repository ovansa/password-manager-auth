"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.analyticsLimiter = exports.licenseLimiter = exports.generalLimiter = exports.oauthRelayLimiter = exports.tokenLimiter = exports.kdfLimiter = exports.registerLimiter = exports.loginLimiter = void 0;
const express_rate_limit_1 = __importDefault(require("express-rate-limit"));
// In the test environment all limiters are skipped so tests never hit 429.
const skipInTest = () => process.env.NODE_ENV === 'test';
function envInt(name, fallback) {
    const raw = process.env[name];
    if (!raw)
        return fallback;
    const parsed = parseInt(raw, 10);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}
function windowMs(envName, fallbackMinutes) {
    return envInt(envName, fallbackMinutes) * 60 * 1000;
}
// Login: brute-force guard at the transport level.
// Per-account lockout inside the handler is a second, independent layer.
exports.loginLimiter = (0, express_rate_limit_1.default)({
    windowMs: windowMs('RATE_LIMIT_LOGIN_WINDOW_MIN', 15),
    max: envInt('RATE_LIMIT_LOGIN_MAX', 10),
    message: {
        error: 'Too many login attempts. Please try again in 15 minutes.',
    },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true,
    skip: skipInTest,
});
// Registration: cap new account creation per IP.
exports.registerLimiter = (0, express_rate_limit_1.default)({
    windowMs: windowMs('RATE_LIMIT_REGISTER_WINDOW_MIN', 60),
    max: envInt('RATE_LIMIT_REGISTER_MAX', 20),
    message: { error: 'Too many registration attempts. Please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
    skip: skipInTest,
});
// KDF params: looked up just before login.
exports.kdfLimiter = (0, express_rate_limit_1.default)({
    windowMs: windowMs('RATE_LIMIT_KDF_WINDOW_MIN', 15),
    max: envInt('RATE_LIMIT_KDF_MAX', 20),
    message: { error: 'Too many requests. Please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
    skip: skipInTest,
});
// Token exchange / refresh.
exports.tokenLimiter = (0, express_rate_limit_1.default)({
    windowMs: windowMs('RATE_LIMIT_TOKEN_WINDOW_MIN', 15),
    max: envInt('RATE_LIMIT_TOKEN_MAX', 20),
    message: { error: 'Too many token requests. Please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
    skip: skipInTest,
});
// OAuth relay polling: extension polls for the auth code.
exports.oauthRelayLimiter = (0, express_rate_limit_1.default)({
    windowMs: windowMs('RATE_LIMIT_OAUTH_RELAY_WINDOW_MIN', 15),
    max: envInt('RATE_LIMIT_OAUTH_RELAY_MAX', 60),
    message: { error: 'Too many requests. Please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
    skip: skipInTest,
});
// General catch-all for any other routes.
exports.generalLimiter = (0, express_rate_limit_1.default)({
    windowMs: windowMs('RATE_LIMIT_GENERAL_WINDOW_MIN', 15),
    max: envInt('RATE_LIMIT_GENERAL_MAX', 100),
    standardHeaders: true,
    legacyHeaders: false,
    skip: skipInTest,
});
// License activation: prevents brute-forcing keys.
exports.licenseLimiter = (0, express_rate_limit_1.default)({
    windowMs: windowMs('RATE_LIMIT_LICENSE_WINDOW_MIN', 60),
    max: envInt('RATE_LIMIT_LICENSE_MAX', 5),
    message: { error: 'Too many activation attempts. Please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
    skip: skipInTest,
});
// Analytics event ingestion.
exports.analyticsLimiter = (0, express_rate_limit_1.default)({
    windowMs: windowMs('RATE_LIMIT_ANALYTICS_WINDOW_MIN', 15),
    max: envInt('RATE_LIMIT_ANALYTICS_MAX', 60),
    standardHeaders: true,
    legacyHeaders: false,
    skip: skipInTest,
});
