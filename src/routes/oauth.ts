import { Router, Request, Response } from 'express';
import axios from 'axios';
import { tokenLimiter, oauthRelayLimiter } from '../middleware/rateLimiters';
import { getCurrentTimestamp } from '../helpers/email';
import { logger } from '../helpers/logger';

const router = Router();

if (!process.env.SERVER_URL) {
  logger.fatal('startup.missing_env', { vars: 'SERVER_URL' });
  process.exit(1);
}

const RELAY_REDIRECT_URI = `${process.env.SERVER_URL}/api/auth/google/callback`;

interface PendingEntry {
  code: string;
  expiry: number;
}

// In-memory store for auth codes relayed from Google (keyed by state token).
// Each entry expires after 5 minutes. This lets any browser/extension origin
// complete the OAuth flow via a single registered redirect URI on this server.
const pendingAuthCodes = new Map<string, PendingEntry>();

// Route: OAuth callback - Google redirects here after user consent.
router.get('/callback', (req: Request, res: Response) => {
  const { code, state, error } = req.query as Record<
    string,
    string | undefined
  >;

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
    if (v.expiry < Date.now()) pendingAuthCodes.delete(k);
  }

  res.send(`
    <html><body>
      <p>Authentication successful! You can close this tab and return to the extension.</p>
      <script>window.close();</script>
    </body></html>
  `);
});

// Route: Extension polls this to retrieve its auth code by state token.
router.get('/code', oauthRelayLimiter, (req: Request, res: Response) => {
  const { state } = req.query as { state?: string };
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
router.get('/redirect-uri', (_req: Request, res: Response) => {
  res.json({ redirect_uri: RELAY_REDIRECT_URI });
});

// Route: Exchange auth code for tokens
router.post('/', tokenLimiter, async (req: Request, res: Response) => {
  const startMs = Date.now();

  try {
    const { code, redirect_uri, code_verifier } = req.body as {
      code?: string;
      redirect_uri?: string;
      code_verifier?: string;
    };

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

    const response = await axios.post(
      'https://oauth2.googleapis.com/token',
      new URLSearchParams(params as Record<string, string>),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
    );

    logger.info('oauth.token_exchange_success', {
      durationMs: Date.now() - startMs,
    });

    res.json({
      access_token: response.data.access_token,
      refresh_token: response.data.refresh_token,
      expires_in: response.data.expires_in,
      timestamp: getCurrentTimestamp(),
    });
  } catch (error) {
    logger.error('oauth.token_exchange_error', error, {
      durationMs: Date.now() - startMs,
    });
    res.status(400).json({ error: 'Authentication failed' });
  }
});

export default router;
