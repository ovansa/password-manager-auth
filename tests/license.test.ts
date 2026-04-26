import request from 'supertest';
import { app } from '../src/app';
import { getMocks } from './getMocks';

const { makeDoc, mockDocRef, mockCollectionRef, mockTransaction, mockDb } =
  getMocks();

const CSRF_HEADERS = { 'X-Requested-With': 'XMLHttpRequest' };

beforeEach(() => {
  jest.clearAllMocks();
  mockDocRef.get.mockResolvedValue(makeDoc(false));
  mockDocRef.set.mockResolvedValue(undefined);
  mockDocRef.update.mockResolvedValue(undefined);
  mockCollectionRef.doc.mockReturnValue(mockDocRef);
});

const validKeyData = {
  revoked: false,
  use_count: 0,
  max_uses: 1,
  activated_by: null,
  duration_days: 365,
  plan: 'annual',
};

// ── POST /api/license/activate ─────────────────────────────────────────────

describe('POST /api/license/activate', () => {
  test('rejects without CSRF header', async () => {
    const res = await request(app)
      .post('/api/license/activate')
      .send({ email: 'user@example.com', key: 'SOME-KEY' });
    expect(res.status).toBe(403);
  });

  test('rejects missing email or key', async () => {
    const res = await request(app)
      .post('/api/license/activate')
      .set(CSRF_HEADERS)
      .send({ email: 'user@example.com' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/missing email or key/i);
  });

  test('rejects invalid (non-existent) license key', async () => {
    mockTransaction.get.mockResolvedValue(makeDoc(false));

    const res = await request(app)
      .post('/api/license/activate')
      .set(CSRF_HEADERS)
      .send({ email: 'user@example.com', key: 'INVALID-KEY' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/invalid license key/i);
  });

  test('rejects revoked key', async () => {
    mockTransaction.get.mockResolvedValue(
      makeDoc(true, { ...validKeyData, revoked: true }),
    );

    const res = await request(app)
      .post('/api/license/activate')
      .set(CSRF_HEADERS)
      .send({ email: 'user@example.com', key: 'REVOKED-KEY' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/revoked/i);
  });

  test('rejects key with unknown plan', async () => {
    mockTransaction.get.mockResolvedValue(
      makeDoc(true, { ...validKeyData, plan: 'enterprise' }),
    );

    const res = await request(app)
      .post('/api/license/activate')
      .set(CSRF_HEADERS)
      .send({ email: 'user@example.com', key: 'UNKNOWN-PLAN-KEY' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/invalid license key/i);
  });

  test('rejects key already used by a different email', async () => {
    mockTransaction.get.mockResolvedValue(
      makeDoc(true, {
        ...validKeyData,
        use_count: 1,
        max_uses: 1,
        activated_by: 'other@example.com',
      }),
    );

    const res = await request(app)
      .post('/api/license/activate')
      .set(CSRF_HEADERS)
      .send({ email: 'user@example.com', key: 'USED-KEY' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/already been used/i);
  });

  test('activates a valid key successfully', async () => {
    mockTransaction.get.mockResolvedValue(makeDoc(true, validKeyData));
    mockTransaction.update.mockReturnThis();
    mockTransaction.set.mockReturnThis();
    mockDb.runTransaction.mockImplementationOnce(
      async (fn: (tx: typeof mockTransaction) => Promise<unknown>) =>
        fn(mockTransaction),
    );

    const res = await request(app)
      .post('/api/license/activate')
      .set(CSRF_HEADERS)
      .send({ email: 'user@example.com', key: 'VALID-KEY' });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.plan).toBe('annual');
    expect(res.body).toHaveProperty('expires_at');
    expect(res.body.license).toMatchObject({ status: 'active', plan: 'annual' });
    expect(res.body.license.token).toEqual(expect.any(String));
  });

  test('allows re-activation by the same email', async () => {
    mockTransaction.get.mockResolvedValue(
      makeDoc(true, {
        ...validKeyData,
        use_count: 1,
        max_uses: 1,
        activated_by: 'user@example.com',
      }),
    );

    const res = await request(app)
      .post('/api/license/activate')
      .set(CSRF_HEADERS)
      .send({ email: 'user@example.com', key: 'MY-KEY' });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  test('handles null duration_days (lifetime license)', async () => {
    mockTransaction.get.mockResolvedValue(
      makeDoc(true, { ...validKeyData, duration_days: null }),
    );

    const res = await request(app)
      .post('/api/license/activate')
      .set(CSRF_HEADERS)
      .send({ email: 'user@example.com', key: 'LIFETIME-KEY' });
    expect(res.status).toBe(200);
    expect(res.body.expires_at).toBeNull();
  });

  test('returns 500 on unexpected Firestore error during transaction', async () => {
    mockDb.runTransaction.mockRejectedValueOnce(
      new Error('Transaction failed'),
    );

    const res = await request(app)
      .post('/api/license/activate')
      .set(CSRF_HEADERS)
      .send({ email: 'user@example.com', key: 'SOME-KEY' });
    expect(res.status).toBe(500);
    expect(res.body.error).toMatch(/activation failed/i);
  });
});

// ── POST /api/license/validate ────────────────────────────────────────────

describe('POST /api/license/validate', () => {
  test('returns signed free license when no subscription exists', async () => {
    mockDocRef.get.mockResolvedValue(makeDoc(false));

    const res = await request(app)
      .post('/api/license/validate')
      .set(CSRF_HEADERS)
      .send({ email: 'free@example.com' });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.license).toMatchObject({ status: 'free', plan: 'free' });
    expect(res.body.license.token).toEqual(expect.any(String));
  });

  test('returns signed active license for subscribed user', async () => {
    mockDocRef.get.mockResolvedValue(
      makeDoc(true, { status: 'active', plan: 'annual', expires_at: null }),
    );

    const res = await request(app)
      .post('/api/license/validate')
      .set(CSRF_HEADERS)
      .send({ email: 'user@example.com' });

    expect(res.status).toBe(200);
    expect(res.body.license).toMatchObject({ status: 'active', plan: 'annual' });
    expect(res.body.license.token).toEqual(expect.any(String));
  });
});

// ── POST /api/subscription/check-eligibility ──────────────────────────────

describe('POST /api/subscription/check-eligibility', () => {
  test('returns false when email missing', async () => {
    const res = await request(app)
      .post('/api/subscription/check-eligibility')
      .set(CSRF_HEADERS)
      .send({});
    expect(res.status).toBe(400);
    expect(res.body.eligible).toBe(false);
  });

  test('returns false when user does not exist', async () => {
    mockDocRef.get.mockResolvedValue(makeDoc(false));
    const res = await request(app)
      .post('/api/subscription/check-eligibility')
      .set(CSRF_HEADERS)
      .send({ email: 'nobody@example.com' });
    expect(res.status).toBe(200);
    expect(res.body.eligible).toBe(false);
  });

  test('returns true for subscribed user', async () => {
    mockDocRef.get.mockResolvedValue(makeDoc(true, { isSubscribed: true }));
    const res = await request(app)
      .post('/api/subscription/check-eligibility')
      .set(CSRF_HEADERS)
      .send({ email: 'subscriber@example.com' });
    expect(res.status).toBe(200);
    expect(res.body.eligible).toBe(true);
  });

  test('returns false for unsubscribed user', async () => {
    mockDocRef.get.mockResolvedValue(makeDoc(true, { isSubscribed: false }));
    const res = await request(app)
      .post('/api/subscription/check-eligibility')
      .set(CSRF_HEADERS)
      .send({ email: 'free@example.com' });
    expect(res.status).toBe(200);
    expect(res.body.eligible).toBe(false);
  });

  test('returns eligible:false (not 500) when Firestore throws during status check', async () => {
    // checkSubscriptionStatus swallows errors and returns false - eligibility
    // failures must never cause a 500 visible to the client
    mockDocRef.get.mockRejectedValueOnce(new Error('Firestore unavailable'));

    const res = await request(app)
      .post('/api/subscription/check-eligibility')
      .set(CSRF_HEADERS)
      .send({ email: 'user@example.com' });
    expect(res.status).toBe(200);
    expect(res.body.eligible).toBe(false);
  });
});
