import request from 'supertest';
import bcrypt from 'bcrypt';
import { app } from '../src/app';
import { getMocks } from './getMocks';

const { makeDoc, mockDocRef, mockCollectionRef, mockBatch } = getMocks();

const CSRF_HEADERS = { 'X-Requested-With': 'XMLHttpRequest' };

beforeEach(() => {
  jest.clearAllMocks();
  mockDocRef.get.mockResolvedValue(makeDoc(false));
  mockDocRef.set.mockResolvedValue(undefined);
  mockDocRef.update.mockResolvedValue(undefined);
  mockCollectionRef.doc.mockReturnValue(mockDocRef);
  mockBatch.commit.mockResolvedValue(undefined);
});

// ── /api/auth/register ─────────────────────────────────────────────────────

describe('POST /api/auth/register', () => {
  const validBody = {
    email: 'user@example.com',
    passwordHash: 'abc123hash',
    kdfIterations: 310000,
    kdfType: 'pbkdf2-sha256',
    licenseKey: 'VALID-LICENSE-KEY',
  };

  const validKeyData = {
    revoked: false,
    use_count: 0,
    max_uses: 1,
    activated_by: null,
    duration_days: 365,
    plan: 'pro',
  };

  test('rejects without CSRF header', async () => {
    const res = await request(app).post('/api/auth/register').send(validBody);
    expect(res.status).toBe(403);
  });

  test('rejects missing fields', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .set(CSRF_HEADERS)
      .send({ email: 'user@example.com' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/missing required fields/i);
  });

  test('rejects invalid email', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .set(CSRF_HEADERS)
      .send({ ...validBody, email: 'not-an-email' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/invalid email/i);
  });

  test('rejects kdfIterations out of range', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .set(CSRF_HEADERS)
      .send({ ...validBody, kdfIterations: 50000 });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/kdf iterations/i);
  });

  test('rejects unknown kdfType', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .set(CSRF_HEADERS)
      .send({ ...validBody, kdfType: 'md5' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/invalid kdf type/i);
  });

  test('rejects when user already exists', async () => {
    mockDocRef.get.mockResolvedValue(makeDoc(true, { email: 'user@example.com' }));

    const res = await request(app)
      .post('/api/auth/register')
      .set(CSRF_HEADERS)
      .send(validBody);
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/registration unsuccessful/i);
  });

  test('rejects invalid license key', async () => {
    mockDocRef.get
      .mockResolvedValueOnce(makeDoc(false))
      .mockResolvedValueOnce(makeDoc(false));

    const res = await request(app)
      .post('/api/auth/register')
      .set(CSRF_HEADERS)
      .send(validBody);
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/invalid license key/i);
  });

  test('rejects revoked license key', async () => {
    mockDocRef.get
      .mockResolvedValueOnce(makeDoc(false))
      .mockResolvedValueOnce(makeDoc(true, { ...validKeyData, revoked: true }));

    const res = await request(app)
      .post('/api/auth/register')
      .set(CSRF_HEADERS)
      .send(validBody);
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/invalid license key/i);
  });

  test('rejects license key already used by someone else', async () => {
    mockDocRef.get
      .mockResolvedValueOnce(makeDoc(false))
      .mockResolvedValueOnce(makeDoc(true, {
        ...validKeyData,
        use_count: 1,
        max_uses: 1,
        activated_by: 'other@example.com',
      }));

    const res = await request(app)
      .post('/api/auth/register')
      .set(CSRF_HEADERS)
      .send(validBody);
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/already been used/i);
  });

  test('registers user successfully', async () => {
    mockDocRef.get
      .mockResolvedValueOnce(makeDoc(false))
      .mockResolvedValueOnce(makeDoc(true, validKeyData));

    const res = await request(app)
      .post('/api/auth/register')
      .set(CSRF_HEADERS)
      .send(validBody);
    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);
    expect(bcrypt.hash).toHaveBeenCalledWith(validBody.passwordHash, 12);
    expect(mockBatch.commit).toHaveBeenCalled();
  });

  test('returns 500 on unexpected Firestore error', async () => {
    mockDocRef.get.mockRejectedValueOnce(new Error('Firestore unavailable'));

    const res = await request(app)
      .post('/api/auth/register')
      .set(CSRF_HEADERS)
      .send(validBody);
    expect(res.status).toBe(500);
    expect(res.body.error).toMatch(/registration failed/i);
  });
});

// ── /api/auth/login ────────────────────────────────────────────────────────

describe('POST /api/auth/login', () => {
  const validUser = {
    email: 'user@example.com',
    authHash: 'hashed_value',
    kdfIterations: 310000,
    kdfType: 'pbkdf2-sha256',
    loginAttempts: 0,
    lockedUntil: null,
    isSubscribed: true,
  };

  test('rejects without CSRF header', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'user@example.com', passwordHash: 'hash' });
    expect(res.status).toBe(403);
  });

  test('rejects missing credentials', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .set(CSRF_HEADERS)
      .send({ email: 'user@example.com' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/missing credentials/i);
  });

  test('returns 401 for non-existent user (with dummy hash to prevent timing)', async () => {
    mockDocRef.get.mockResolvedValue(makeDoc(false));

    const res = await request(app)
      .post('/api/auth/login')
      .set(CSRF_HEADERS)
      .send({ email: 'nobody@example.com', passwordHash: 'hash' });
    expect(res.status).toBe(401);
    expect(bcrypt.hash).toHaveBeenCalledWith('dummy_password', 12);
  });

  test('returns 423 when account is locked', async () => {
    const futureDate = { toDate: () => new Date(Date.now() + 60_000) };
    mockDocRef.get.mockResolvedValue(makeDoc(true, { ...validUser, lockedUntil: futureDate }));

    const res = await request(app)
      .post('/api/auth/login')
      .set(CSRF_HEADERS)
      .send({ email: 'user@example.com', passwordHash: 'hash' });
    expect(res.status).toBe(423);
    expect(res.body.error).toMatch(/locked/i);
  });

  test('returns 401 and increments attempts on wrong password', async () => {
    (bcrypt.compare as jest.Mock).mockResolvedValueOnce(false);
    mockDocRef.get.mockResolvedValue(makeDoc(true, validUser));

    const res = await request(app)
      .post('/api/auth/login')
      .set(CSRF_HEADERS)
      .send({ email: 'user@example.com', passwordHash: 'wronghash' });
    expect(res.status).toBe(401);
    expect(mockDocRef.update).toHaveBeenCalledWith(
      expect.objectContaining({ loginAttempts: 1 }),
    );
  });

  test('locks account after 5 failed attempts', async () => {
    (bcrypt.compare as jest.Mock).mockResolvedValueOnce(false);
    mockDocRef.get.mockResolvedValue(makeDoc(true, { ...validUser, loginAttempts: 4 }));

    const res = await request(app)
      .post('/api/auth/login')
      .set(CSRF_HEADERS)
      .send({ email: 'user@example.com', passwordHash: 'wronghash' });
    expect(res.status).toBe(401);
    const updateCall = (mockDocRef.update as jest.Mock).mock.calls[0][0] as Record<string, unknown>;
    expect(updateCall).toHaveProperty('lockedUntil');
    expect(updateCall['lockedUntil']).toBeInstanceOf(Date);
  });

  test('returns user and license on successful login', async () => {
    mockDocRef.get
      .mockResolvedValueOnce(makeDoc(true, validUser))
      .mockResolvedValueOnce(makeDoc(true, { status: 'active', plan: 'pro', expires_at: null }));

    const res = await request(app)
      .post('/api/auth/login')
      .set(CSRF_HEADERS)
      .send({ email: 'user@example.com', passwordHash: 'correcthash' });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.user).toMatchObject({
      email: 'user@example.com',
      kdfIterations: 310000,
      kdfType: 'pbkdf2-sha256',
    });
    expect(res.body.license).toMatchObject({ status: 'active', plan: 'pro' });
  });

  test('marks expired license and returns expired status', async () => {
    const pastDate = { toDate: () => new Date('2020-01-01') };
    mockDocRef.get
      .mockResolvedValueOnce(makeDoc(true, validUser))
      .mockResolvedValueOnce(makeDoc(true, { status: 'active', plan: 'pro', expires_at: pastDate }));

    const res = await request(app)
      .post('/api/auth/login')
      .set(CSRF_HEADERS)
      .send({ email: 'user@example.com', passwordHash: 'correcthash' });
    expect(res.status).toBe(200);
    expect(res.body.license.status).toBe('expired');
  });

  test('returns license: none when no subscription exists', async () => {
    mockDocRef.get
      .mockResolvedValueOnce(makeDoc(true, validUser))
      .mockResolvedValueOnce(makeDoc(false));

    const res = await request(app)
      .post('/api/auth/login')
      .set(CSRF_HEADERS)
      .send({ email: 'user@example.com', passwordHash: 'correcthash' });
    expect(res.status).toBe(200);
    expect(res.body.license).toEqual({ status: 'none', plan: null, expires_at: null });
  });

  test('returns 500 on unexpected Firestore error', async () => {
    mockDocRef.get.mockRejectedValueOnce(new Error('Firestore unavailable'));

    const res = await request(app)
      .post('/api/auth/login')
      .set(CSRF_HEADERS)
      .send({ email: 'user@example.com', passwordHash: 'hash' });
    expect(res.status).toBe(500);
    expect(res.body.error).toMatch(/login failed/i);
  });
});

// ── /api/auth/kdf-params ───────────────────────────────────────────────────

describe('GET /api/auth/kdf-params', () => {
  test('rejects missing email', async () => {
    const res = await request(app).get('/api/auth/kdf-params');
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/email required/i);
  });

  test('rejects invalid email format', async () => {
    const res = await request(app)
      .get('/api/auth/kdf-params')
      .query({ email: 'notanemail' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/invalid email/i);
  });

  test('returns defaults for non-existent user (prevents enumeration)', async () => {
    mockDocRef.get.mockResolvedValue(makeDoc(false));
    const res = await request(app)
      .get('/api/auth/kdf-params')
      .query({ email: 'unknown@example.com' });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ iterations: 310000, type: 'pbkdf2-sha256' });
  });

  test('returns user KDF params for existing user', async () => {
    mockDocRef.get.mockResolvedValue(makeDoc(true, {
      kdfIterations: 500000,
      kdfType: 'pbkdf2-sha512',
    }));
    const res = await request(app)
      .get('/api/auth/kdf-params')
      .query({ email: 'user@example.com' });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ iterations: 500000, type: 'pbkdf2-sha512' });
  });

  test('returns 500 on unexpected Firestore error', async () => {
    mockDocRef.get.mockRejectedValueOnce(new Error('Firestore unavailable'));

    const res = await request(app)
      .get('/api/auth/kdf-params')
      .query({ email: 'user@example.com' });
    expect(res.status).toBe(500);
    expect(res.body.error).toMatch(/failed to get parameters/i);
  });
});
