import rateLimit from 'express-rate-limit';

// In the test environment all limiters are skipped so tests never hit 429.
const skipInTest = (): boolean => process.env.NODE_ENV === 'test';

function envInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function windowMs(envName: string, fallbackMinutes: number): number {
  return envInt(envName, fallbackMinutes) * 60 * 1000;
}

// Login: brute-force guard at the transport level.
// Per-account lockout inside the handler is a second, independent layer.
export const loginLimiter = rateLimit({
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
export const registerLimiter = rateLimit({
  windowMs: windowMs('RATE_LIMIT_REGISTER_WINDOW_MIN', 60),
  max: envInt('RATE_LIMIT_REGISTER_MAX', 20),
  message: { error: 'Too many registration attempts. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  skip: skipInTest,
});

// KDF params: looked up just before login.
export const kdfLimiter = rateLimit({
  windowMs: windowMs('RATE_LIMIT_KDF_WINDOW_MIN', 15),
  max: envInt('RATE_LIMIT_KDF_MAX', 20),
  message: { error: 'Too many requests. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  skip: skipInTest,
});

// Token exchange / refresh.
export const tokenLimiter = rateLimit({
  windowMs: windowMs('RATE_LIMIT_TOKEN_WINDOW_MIN', 15),
  max: envInt('RATE_LIMIT_TOKEN_MAX', 20),
  message: { error: 'Too many token requests. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  skip: skipInTest,
});

// OAuth relay polling: extension polls for the auth code.
export const oauthRelayLimiter = rateLimit({
  windowMs: windowMs('RATE_LIMIT_OAUTH_RELAY_WINDOW_MIN', 15),
  max: envInt('RATE_LIMIT_OAUTH_RELAY_MAX', 60),
  message: { error: 'Too many requests. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  skip: skipInTest,
});

// General catch-all for any other routes.
export const generalLimiter = rateLimit({
  windowMs: windowMs('RATE_LIMIT_GENERAL_WINDOW_MIN', 15),
  max: envInt('RATE_LIMIT_GENERAL_MAX', 100),
  standardHeaders: true,
  legacyHeaders: false,
  skip: skipInTest,
});

// License activation: prevents brute-forcing keys.
export const licenseLimiter = rateLimit({
  windowMs: windowMs('RATE_LIMIT_LICENSE_WINDOW_MIN', 60),
  max: envInt('RATE_LIMIT_LICENSE_MAX', 5),
  message: { error: 'Too many activation attempts. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  skip: skipInTest,
});

// Analytics event ingestion.
export const analyticsLimiter = rateLimit({
  windowMs: windowMs('RATE_LIMIT_ANALYTICS_WINDOW_MIN', 15),
  max: envInt('RATE_LIMIT_ANALYTICS_MAX', 60),
  standardHeaders: true,
  legacyHeaders: false,
  skip: skipInTest,
});
