import request from 'supertest';
import { app } from '../src/app';
import { getMocks } from './getMocks';

const { makeDoc, mockDocRef, mockCollectionRef } = getMocks();

beforeEach(() => {
  jest.clearAllMocks();
  mockDocRef.get.mockResolvedValue(makeDoc(false));
  mockCollectionRef.add.mockResolvedValue({ id: 'new-event-id' });
});

const validInstallId = '550e8400-e29b-41d4-a716-446655440000';

// ── POST /api/analytics/event ──────────────────────────────────────────────

describe('POST /api/analytics/event', () => {
  test('rejects missing or invalid event name', async () => {
    const res = await request(app)
      .post('/api/analytics/event')
      .send({ event: 'unknown_event', installId: validInstallId });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/invalid event/i);
  });

  test('rejects missing installId', async () => {
    const res = await request(app)
      .post('/api/analytics/event')
      .send({ event: 'vault_unlocked' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/invalid installId/i);
  });

  test('rejects malformed installId (not a UUID)', async () => {
    const res = await request(app)
      .post('/api/analytics/event')
      .send({ event: 'vault_unlocked', installId: 'not-a-uuid' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/invalid installId/i);
  });

  test('accepts valid event and persists it', async () => {
    const res = await request(app)
      .post('/api/analytics/event')
      .send({ event: 'vault_unlocked', installId: validInstallId });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(mockCollectionRef.add).toHaveBeenCalledWith(
      expect.objectContaining({ event: 'vault_unlocked', installId: validInstallId }),
    );
  });

  test('scrubs nested objects from meta, allows primitives', async () => {
    const res = await request(app)
      .post('/api/analytics/event')
      .send({
        event: 'autofill_succeeded',
        installId: validInstallId,
        meta: {
          domain: 'example.com',
          count: 3,
          success: true,
          nested: { secret: 'x' },
        },
      });
    expect(res.status).toBe(200);
    const savedDoc = (mockCollectionRef.add as jest.Mock).mock.calls[0][0] as Record<string, unknown>;
    expect(savedDoc['meta']).toEqual({ domain: 'example.com', count: 3, success: true });
    expect(savedDoc['meta']).not.toHaveProperty('nested');
  });

  test('returns 200 ok:false (not an error) on Firestore failure', async () => {
    mockCollectionRef.add.mockRejectedValueOnce(new Error('Firestore unavailable'));

    const res = await request(app)
      .post('/api/analytics/event')
      .send({ event: 'vault_locked', installId: validInstallId });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(false);
  });

  test('uses provided ts timestamp instead of server time', async () => {
    const clientTs = '2024-06-15T12:00:00.000Z';

    const res = await request(app)
      .post('/api/analytics/event')
      .send({ event: 'vault_unlocked', installId: validInstallId, ts: clientTs });
    expect(res.status).toBe(200);
    const savedDoc = (mockCollectionRef.add as jest.Mock).mock.calls[0][0] as Record<string, unknown>;
    expect(savedDoc['ts']).toEqual(new Date(clientTs));
  });

  test('accepts all valid event names', async () => {
    const validEvents = [
      'vault_created', 'vault_unlocked', 'vault_locked',
      'autofill_triggered', 'autofill_succeeded',
      'password_saved', 'password_deleted', 'password_generated',
      'sync_succeeded', 'sync_failed',
      'export_completed', 'import_completed',
      'license_activated', 'license_validation_failed',
    ];

    for (const event of validEvents) {
      jest.clearAllMocks();
      mockCollectionRef.add.mockResolvedValue({ id: 'id' });
      const res = await request(app)
        .post('/api/analytics/event')
        .send({ event, installId: validInstallId });
      expect(res.status).toBe(200);
      expect(res.body.ok).toBe(true);
    }
  });
});

// ── GET /api/config ────────────────────────────────────────────────────────

describe('GET /api/config', () => {
  test('returns observabilityEnabled flag', async () => {
    const res = await request(app).get('/api/config');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('observabilityEnabled');
    expect(typeof res.body.observabilityEnabled).toBe('boolean');
  });
});

// ── 404 handler ────────────────────────────────────────────────────────────

describe('404 handler', () => {
  test('returns 404 for unknown routes', async () => {
    const res = await request(app).get('/api/nonexistent');
    expect(res.status).toBe(404);
    expect(res.body.error).toMatch(/endpoint not found/i);
  });
});

// ── CORS ───────────────────────────────────────────────────────────────────

describe('CORS', () => {
  test('allows requests from chrome-extension:// origins', async () => {
    const res = await request(app)
      .get('/api/config')
      .set('Origin', 'chrome-extension://abcdefghijklmnopabcdefghijklmnop');
    expect(res.status).toBe(200);
    expect(res.headers['access-control-allow-origin']).toBe(
      'chrome-extension://abcdefghijklmnopabcdefghijklmnop',
    );
  });

  test('allows requests from moz-extension:// origins', async () => {
    const res = await request(app)
      .get('/api/config')
      .set('Origin', 'moz-extension://some-firefox-extension-id');
    expect(res.status).toBe(200);
    expect(res.headers['access-control-allow-origin']).toBe(
      'moz-extension://some-firefox-extension-id',
    );
  });

  test('blocks requests from disallowed origins', async () => {
    // CORS rejection calls next(error), which hits the global error handler
    jest.spyOn(console, 'error').mockImplementationOnce(() => {});
    const res = await request(app)
      .get('/api/config')
      .set('Origin', 'https://evil.example.com');
    expect(res.status).toBe(500);
    expect(res.body.error).toMatch(/internal server error/i);
  });
});
