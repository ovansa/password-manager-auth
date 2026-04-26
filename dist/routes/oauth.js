"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const axios_1 = __importDefault(require("axios"));
const rateLimiters_1 = require("../middleware/rateLimiters");
const email_1 = require("../helpers/email");
const logger_1 = require("../helpers/logger");
const router = (0, express_1.Router)();
if (!process.env.SERVER_URL) {
    logger_1.logger.fatal('startup.missing_env', { vars: 'SERVER_URL' });
    process.exit(1);
}
const RELAY_REDIRECT_URI = `${process.env.SERVER_URL}/api/auth/google/callback`;
// In-memory store for auth codes relayed from Google (keyed by state token).
// Each entry expires after 5 minutes. This lets any browser/extension origin
// complete the OAuth flow via a single registered redirect URI on this server.
const pendingAuthCodes = new Map();
// Route: OAuth callback - Google redirects here after user consent.
router.get('/callback', (req, res) => {
    const { code, state, error } = req.query;
    if (error || !code || !state) {
        res.status(400).send(`
      <html><body>
        <p>Authentication failed: ${error ?? 'Missing parameters'}.</p>
        <p>You can close this tab.</p>
      </body></html>
    `);
        return;
    }
    pendingAuthCodes.set(state, { code, expiry: Date.now() + 5 * 60 * 1000 });
    // Clean up expired entries
    for (const [k, v] of pendingAuthCodes) {
        if (v.expiry < Date.now())
            pendingAuthCodes.delete(k);
    }
    res.send(`
    <html><body>
      <p>Authentication successful! You can close this tab and return to the extension.</p>
      <script>window.close();</script>
    </body></html>
  `);
});
// Route: Extension polls this to retrieve its auth code by state token.
router.get('/code', rateLimiters_1.oauthRelayLimiter, (req, res) => {
    const { state } = req.query;
    if (!state) {
        res.status(400).json({ error: 'Missing state' });
        return;
    }
    const entry = pendingAuthCodes.get(state);
    if (!entry) {
        res.status(404).json({ pending: true });
        return;
    }
    if (entry.expiry < Date.now()) {
        pendingAuthCodes.delete(state);
        res.status(410).json({ error: 'Code expired' });
        return;
    }
    pendingAuthCodes.delete(state); // one-time use
    res.json({ code: entry.code });
});
// Route: Returns the relay redirect URI so the extension doesn't need to hardcode it.
router.get('/redirect-uri', (_req, res) => {
    res.json({ redirect_uri: RELAY_REDIRECT_URI });
});
// Route: Exchange auth code for tokens
router.post('/', rateLimiters_1.tokenLimiter, async (req, res) => {
    const startMs = Date.now();
    try {
        const { code, redirect_uri, code_verifier } = req.body;
        if (!redirect_uri) {
            res.status(400).json({ error: 'Missing redirect_uri' });
            return;
        }
        if (!code_verifier) {
            res.status(400).json({ error: 'Missing code_verifier' });
            return;
        }
        const params = {
            code,
            client_id: process.env.GOOGLE_CLIENT_ID,
            client_secret: process.env.GOOGLE_CLIENT_SECRET,
            redirect_uri,
            grant_type: 'authorization_code',
            code_verifier,
        };
        const response = await axios_1.default.post('https://oauth2.googleapis.com/token', new URLSearchParams(params), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
        logger_1.logger.info('oauth.token_exchange_success', {
            durationMs: Date.now() - startMs,
        });
        res.json({
            access_token: response.data.access_token,
            refresh_token: response.data.refresh_token,
            expires_in: response.data.expires_in,
            timestamp: (0, email_1.getCurrentTimestamp)(),
        });
    }
    catch (error) {
        logger_1.logger.error('oauth.token_exchange_error', error, {
            durationMs: Date.now() - startMs,
        });
        res.status(400).json({ error: 'Authentication failed' });
    }
});
exports.default = router;
