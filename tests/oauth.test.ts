import request from 'supertest';
import axios from 'axios';
import { app } from '../src/app';
import { getMocks } from './getMocks';

const { makeDoc, mockDocRef } = getMocks();

beforeEach(() => {
  jest.clearAllMocks();
  mockDocRef.get.mockResolvedValue(makeDoc(false));
});

// ── /api/auth/google/callback ──────────────────────────────────────────────

describe('GET /api/auth/google/callback', () => {
  test('returns 400 on error param', async () => {
    const res = await request(app)
      .get('/api/auth/google/callback')
      .query({ error: 'access_denied' });
    expect(res.status).toBe(400);
    expect(res.text).toMatch(/access_denied/);
  });

  test('returns 400 when code or state missing', async () => {
    const res = await request(app)
      .get('/api/auth/google/callback')
      .query({ code: 'authcode' }); // no state
    expect(res.status).toBe(400);
  });

  test('stores code and returns success page', async () => {
    const res = await request(app)
      .get('/api/auth/google/callback')
      .query({ code: 'myauthcode', state: 'mystate123' });
    expect(res.status).toBe(200);
    expect(res.text).toMatch(/successful/i);
  });
});

// ── /api/auth/google/code ──────────────────────────────────────────────────

describe('GET /api/auth/google/code', () => {
  test('returns 400 when state missing', async () => {
    const res = await request(app).get('/api/auth/google/code');
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/missing state/i);
  });

  test('returns 404 (pending) when state not found', async () => {
    const res = await request(app)
      .get('/api/auth/google/code')
      .query({ state: 'nonexistent' });
    expect(res.status).toBe(404);
    expect(res.body.pending).toBe(true);
  });

  test('returns code when state exists (one-time use)', async () => {
    await request(app)
      .get('/api/auth/google/callback')
      .query({ code: 'secretcode', state: 'validstate' });

    const res = await request(app)
      .get('/api/auth/google/code')
      .query({ state: 'validstate' });
    expect(res.status).toBe(200);
    expect(res.body.code).toBe('secretcode');

    // Should be gone after retrieval (one-time use)
    const res2 = await request(app)
      .get('/api/auth/google/code')
      .query({ state: 'validstate' });
    expect(res2.status).toBe(404);
  });

  test('returns 410 when code has expired', async () => {
    // Store a code then advance time past the 5-minute expiry
    await request(app)
      .get('/api/auth/google/callback')
      .query({ code: 'expiredcode', state: 'expiredstate' });

    jest.useFakeTimers();
    jest.advanceTimersByTime(6 * 60 * 1000); // 6 minutes

    const res = await request(app)
      .get('/api/auth/google/code')
      .query({ state: 'expiredstate' });
    expect(res.status).toBe(410);
    expect(res.body.error).toMatch(/expired/i);

    jest.useRealTimers();
  });
});

// ── /api/auth/google/redirect-uri ─────────────────────────────────────────

describe('GET /api/auth/google/redirect-uri', () => {
  test('returns redirect_uri', async () => {
    const res = await request(app).get('/api/auth/google/redirect-uri');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('redirect_uri');
    expect(res.body.redirect_uri).toContain('/api/auth/google/callback');
  });
});

// ── POST /api/auth/google (token exchange) ─────────────────────────────────

describe('POST /api/auth/google', () => {
  test('rejects missing redirect_uri', async () => {
    const res = await request(app)
      .post('/api/auth/google')
      .send({ code: 'authcode', code_verifier: 'verifier' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/redirect_uri/i);
  });

  test('rejects missing code_verifier', async () => {
    const res = await request(app)
      .post('/api/auth/google')
      .send({ code: 'authcode', redirect_uri: 'https://example.com/cb' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/code_verifier/i);
  });

  test('exchanges code for tokens', async () => {
    const res = await request(app)
      .post('/api/auth/google')
      .send({
        code: 'authcode',
        redirect_uri: 'https://example.com/cb',
        code_verifier: 'pkce_verifier',
      });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('access_token', 'test_access_token');
    expect(res.body).toHaveProperty('refresh_token', 'test_refresh_token');
  });

  test('returns 400 on OAuth provider error', async () => {
    (axios.post as jest.Mock).mockRejectedValueOnce(
      Object.assign(new Error('invalid_grant'), {
        response: { data: { error: 'invalid_grant' } },
      }),
    );

    const res = await request(app)
      .post('/api/auth/google')
      .send({
        code: 'badcode',
        redirect_uri: 'https://example.com/cb',
        code_verifier: 'pkce_verifier',
      });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/authentication failed/i);
  });
});

// ── POST /api/auth/refresh ─────────────────────────────────────────────────

describe('POST /api/auth/refresh', () => {
  test('refreshes access token successfully', async () => {
    const res = await request(app)
      .post('/api/auth/refresh')
      .send({ refresh_token: 'valid_refresh_token' });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('access_token', 'test_access_token');
    expect(res.body).toHaveProperty('expires_in', 3600);
  });

  test('returns 400 on refresh failure', async () => {
    (axios.post as jest.Mock).mockRejectedValueOnce(
      Object.assign(new Error('token_expired'), {
        response: { data: { error: 'token_expired' } },
      }),
    );

    const res = await request(app)
      .post('/api/auth/refresh')
      .send({ refresh_token: 'expired_token' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/token refresh failed/i);
  });
});
