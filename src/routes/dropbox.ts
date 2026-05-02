import { Router, Request, Response } from 'express';
import axios from 'axios';
import { tokenLimiter, oauthRelayLimiter } from '../middleware/rateLimiters';
import { getRequiredEnv } from '../config/env';
import { getCurrentTimestamp } from '../helpers/email';
import { logger } from '../helpers/logger';

const router = Router();
const DROPBOX_TOKEN_URL = 'https://api.dropbox.com/oauth2/token';
const RELAY_REDIRECT_URI = `${getRequiredEnv('SERVER_URL')}/api/auth/dropbox/callback`;

interface PendingEntry {
  code: string;
  expiry: number;
}

const pendingAuthCodes = new Map<string, PendingEntry>();

function getDropboxClientId(): string | undefined {
  return process.env.DROPBOX_CLIENT_ID || process.env.DROPBOX_APP_KEY;
}

// Route: OAuth callback - Dropbox redirects here after user consent.
router.get('/callback', (req: Request, res: Response) => {
  const { code, state, error, error_description } = req.query as Record<
    string,
    string | undefined
  >;

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
    if (v.expiry < Date.now()) pendingAuthCodes.delete(k);
  }

  res.send(`
    <html><body>
      <p>Dropbox authentication successful! You can close this tab and return to the extension.</p>
      <script>window.close();</script>
    </body></html>
  `);
});

// Route: Extension polls this to retrieve its Dropbox auth code by state token.
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

  pendingAuthCodes.delete(state);
  res.json({ code: entry.code });
});

router.get('/redirect-uri', (_req: Request, res: Response) => {
  res.json({ redirect_uri: RELAY_REDIRECT_URI });
});

// Route: Exchange Dropbox auth code for short-lived access token + refresh token.
router.post('/', tokenLimiter, async (req: Request, res: Response) => {
  const startMs = Date.now();

  try {
    const { code, redirect_uri, code_verifier } = req.body as {
      code?: string;
      redirect_uri?: string;
      code_verifier?: string;
    };
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

    const params: Record<string, string> = {
      code,
      grant_type: 'authorization_code',
      client_id: clientId,
      redirect_uri,
      code_verifier,
    };

    if (process.env.DROPBOX_CLIENT_SECRET) {
      params.client_secret = process.env.DROPBOX_CLIENT_SECRET;
    }

    const response = await axios.post(
      DROPBOX_TOKEN_URL,
      new URLSearchParams(params),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
    );

    logger.info('dropbox.token_exchange_success', {
      durationMs: Date.now() - startMs,
    });

    res.json({
      access_token: response.data.access_token,
      refresh_token: response.data.refresh_token,
      expires_in: response.data.expires_in,
      token_type: response.data.token_type,
      account_id: response.data.account_id,
      uid: response.data.uid,
      timestamp: getCurrentTimestamp(),
    });
  } catch (error) {
    logger.error('dropbox.token_exchange_error', error, {
      durationMs: Date.now() - startMs,
    });
    res.status(400).json({ error: 'Dropbox authentication failed' });
  }
});

// Route: Refresh Dropbox access token with a long-lived refresh token.
router.post('/refresh', tokenLimiter, async (req: Request, res: Response) => {
  const startMs = Date.now();

  try {
    const { refresh_token } = req.body as { refresh_token?: string };
    const clientId = getDropboxClientId();

    if (!clientId) {
      res.status(500).json({ error: 'Dropbox is not configured' });
      return;
    }
    if (!refresh_token) {
      res.status(400).json({ error: 'Missing refresh_token' });
      return;
    }

    const params: Record<string, string> = {
      refresh_token,
      grant_type: 'refresh_token',
      client_id: clientId,
    };

    if (process.env.DROPBOX_CLIENT_SECRET) {
      params.client_secret = process.env.DROPBOX_CLIENT_SECRET;
    }

    const response = await axios.post(
      DROPBOX_TOKEN_URL,
      new URLSearchParams(params),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
    );

    logger.info('dropbox.token_refresh_success', {
      durationMs: Date.now() - startMs,
    });

    res.json({
      access_token: response.data.access_token,
      expires_in: response.data.expires_in,
      token_type: response.data.token_type,
      timestamp: getCurrentTimestamp(),
    });
  } catch (error) {
    logger.error('dropbox.token_refresh_error', error, {
      durationMs: Date.now() - startMs,
    });
    res.status(400).json({ error: 'Dropbox token refresh failed' });
  }
});

export default router;
