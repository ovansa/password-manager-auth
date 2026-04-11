"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.app = void 0;
require("dotenv/config");
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const helmet_1 = __importDefault(require("helmet"));
const rateLimiters_1 = require("./middleware/rateLimiters");
const email_1 = require("./helpers/email");
// Firebase must be initialized before any route module imports db.
require("./config/firebase");
const auth_1 = __importDefault(require("./routes/auth"));
const oauth_1 = __importDefault(require("./routes/oauth"));
const license_1 = __importDefault(require("./routes/license"));
const analytics_1 = __importDefault(require("./routes/analytics"));
const config_1 = __importDefault(require("./routes/config"));
const app = (0, express_1.default)();
exports.app = app;
// Security middleware
app.use((0, helmet_1.default)());
app.use(express_1.default.json({ limit: '10mb' }));
// CORS must run before rate limiters so that 429 responses still include
// Access-Control-Allow-Origin and are not blocked by the browser.
const allowedOrigins = [
    ...(process.env.FRONTEND_URL ? [process.env.FRONTEND_URL] : []),
    'http://localhost:3000',
    'http://127.0.0.1:3000',
];
app.use((0, cors_1.default)({
    origin: (origin, callback) => {
        if (!origin ||
            origin.startsWith('chrome-extension://') ||
            origin.startsWith('moz-extension://') ||
            allowedOrigins.includes(origin)) {
            callback(null, true);
        }
        else {
            callback(new Error(`CORS: origin ${origin} not allowed`));
        }
    },
    credentials: true,
}));
// Apply general limiter globally, excluding the OAuth relay poll route.
app.use((req, res, next) => {
    if (req.path === '/api/auth/google/code')
        return next();
    (0, rateLimiters_1.generalLimiter)(req, res, next);
});
// ── Routes ─────────────────────────────────────────────────────────────────
// Order matters: more specific paths must be mounted before broader ones.
// /api/auth/google/* must come before /api/auth/* so the google sub-router
// matches before Express strips the prefix.
app.use('/api/auth/google', oauth_1.default); // /callback, /code, /redirect-uri, POST /
app.use('/api/auth', auth_1.default); // /register, /login, /kdf-params, /refresh
app.use('/api/subscription', license_1.default);
app.use('/api/license', license_1.default);
app.use('/api/analytics', analytics_1.default);
app.use('/api/config', config_1.default);
// ── Error handlers ─────────────────────────────────────────────────────────
// Global error handler (4 params required for Express to treat as error handler)
app.use((error, req, res, _next) => {
    console.error('Unhandled error:', {
        timestamp: (0, email_1.getCurrentTimestamp)(),
        error: error.message,
        stack: error.stack,
        url: req.url,
        method: req.method,
    });
    res.status(500).json({ error: 'Internal server error', timestamp: (0, email_1.getCurrentTimestamp)() });
});
// 404 handler
app.use((_req, res) => {
    res.status(404).json({ error: 'Endpoint not found', timestamp: (0, email_1.getCurrentTimestamp)() });
});
