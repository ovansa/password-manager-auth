"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const axios_1 = __importDefault(require("axios"));
const rateLimiters_1 = require("../middleware/rateLimiters");
const env_1 = require("../config/env");
const email_1 = require("../helpers/email");
const logger_1 = require("../helpers/logger");
const router = (0, express_1.Router)();
const DROPBOX_TOKEN_URL = 'https://api.dropbox.com/oauth2/token';
const RELAY_REDIRECT_URI = `${(0, env_1.getRequiredEnv)('SERVER_URL')}/api/auth/dropbox/callback`;
const pendingAuthCodes = new Map();
function getDropboxClientId() {
    return process.env.DROPBOX_CLIENT_ID || process.env.DROPBOX_APP_KEY;
}
// Route: OAuth callback - Dropbox redirects here after user consent.
router.get('/callback', (req, res) => {
    const { code, state, error, error_description } = req.query;
    if (error || !code || !state) {
        res.status(400).send(`
      <html><body>
        <p>Dropbox authentication failed: ${error_description ?? error ?? 'Missing parameters'}.</p>
        <p>You can close this tab.</p>
      </body></html>
    `);
        return;
    }
    pendingAuthCodes.set(state, { code, expiry: Date.now() + 5 * 60 * 1000 });
    for (const [k, v] of pendingAuthCodes) {
        if (v.expiry < Date.now())
            pendingAuthCodes.delete(k);
    }
    res.send(`
    <html><body>
      <p>Dropbox authentication successful! You can close this tab and return to the extension.</p>
      <script>window.close();</script>
    </body></html>
  `);
});
// Route: Extension polls this to retrieve its Dropbox auth code by state token.
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
    pendingAuthCodes.delete(state);
    res.json({ code: entry.code });
});
router.get('/redirect-uri', (_req, res) => {
    res.json({ redirect_uri: RELAY_REDIRECT_URI });
});
// Route: Exchange Dropbox auth code for short-lived access token + refresh token.
router.post('/', rateLimiters_1.tokenLimiter, async (req, res) => {
    const startMs = Date.now();
    try {
        const { code, redirect_uri, code_verifier } = req.body;
        const clientId = getDropboxClientId();
        if (!clientId) {
            res.status(500).json({ error: 'Dropbox is not configured' });
            return;
        }
        if (!code) {
            res.status(400).json({ error: 'Missing code' });
            return;
        }
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
            grant_type: 'authorization_code',
            client_id: clientId,
            redirect_uri,
            code_verifier,
        };
        if (process.env.DROPBOX_CLIENT_SECRET) {
            params.client_secret = process.env.DROPBOX_CLIENT_SECRET;
        }
        const response = await axios_1.default.post(DROPBOX_TOKEN_URL, new URLSearchParams(params), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
        logger_1.logger.info('dropbox.token_exchange_success', {
            durationMs: Date.now() - startMs,
        });
        res.json({
            access_token: response.data.access_token,
            refresh_token: response.data.refresh_token,
            expires_in: response.data.expires_in,
            token_type: response.data.token_type,
            account_id: response.data.account_id,
            uid: response.data.uid,
            timestamp: (0, email_1.getCurrentTimestamp)(),
        });
    }
    catch (error) {
        logger_1.logger.error('dropbox.token_exchange_error', error, {
            durationMs: Date.now() - startMs,
        });
        res.status(400).json({ error: 'Dropbox authentication failed' });
    }
});
// Route: Refresh Dropbox access token with a long-lived refresh token.
router.post('/refresh', rateLimiters_1.tokenLimiter, async (req, res) => {
    const startMs = Date.now();
    try {
        const { refresh_token } = req.body;
        const clientId = getDropboxClientId();
        if (!clientId) {
            res.status(500).json({ error: 'Dropbox is not configured' });
            return;
        }
        if (!refresh_token) {
            res.status(400).json({ error: 'Missing refresh_token' });
            return;
        }
        const params = {
            refresh_token,
            grant_type: 'refresh_token',
            client_id: clientId,
        };
        if (process.env.DROPBOX_CLIENT_SECRET) {
            params.client_secret = process.env.DROPBOX_CLIENT_SECRET;
        }
        const response = await axios_1.default.post(DROPBOX_TOKEN_URL, new URLSearchParams(params), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
        logger_1.logger.info('dropbox.token_refresh_success', {
            durationMs: Date.now() - startMs,
        });
        res.json({
            access_token: response.data.access_token,
            expires_in: response.data.expires_in,
            token_type: response.data.token_type,
            timestamp: (0, email_1.getCurrentTimestamp)(),
        });
    }
    catch (error) {
        logger_1.logger.error('dropbox.token_refresh_error', error, {
            durationMs: Date.now() - startMs,
        });
        res.status(400).json({ error: 'Dropbox token refresh failed' });
    }
});
exports.default = router;
