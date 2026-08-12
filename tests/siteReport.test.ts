import request from 'supertest';
import { app } from '../src/app';
import { getMocks } from './getMocks';

const { makeDoc, mockDocRef, mockCollectionRef } = getMocks();

beforeEach(() => {
  jest.clearAllMocks();
  mockDocRef.get.mockResolvedValue(makeDoc(false));
  mockCollectionRef.add.mockResolvedValue({ id: 'new-report-id' });
});

const validReport = {
  hostname: 'example.com',
  version: '1.2.3',
  failureType: 'no_button',
};

describe('POST /api/site-report', () => {
  test('accepts a valid report and persists exactly the four fields', async () => {
    const res = await request(app).post('/api/site-report').send(validReport);

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);

    const written = mockCollectionRef.add.mock.calls[0][0];
    expect(written).toEqual({
      hostname: 'example.com',
      version: '1.2.3',
      failureType: 'no_button',
      receivedAt: expect.any(Date),
    });
  });

  test('lowercases and trims the hostname', async () => {
    await request(app)
      .post('/api/site-report')
      .send({ ...validReport, hostname: '  Login.EXAMPLE.co.uk ' });

    expect(mockCollectionRef.add.mock.calls[0][0].hostname).toBe(
      'login.example.co.uk',
    );
  });

  test('rejects a full URL rather than storing a browsing trail', async () => {
    for (const hostname of [
      'https://example.com/login',
      'example.com/account?token=abc',
      'user:pass@example.com',
      'example.com:8080',
    ]) {
      const res = await request(app)
        .post('/api/site-report')
        .send({ ...validReport, hostname });
      expect(res.status).toBe(400);
    }
    expect(mockCollectionRef.add).not.toHaveBeenCalled();
  });

  test('rejects a missing or non-string hostname', async () => {
    for (const hostname of [undefined, '', 42, { a: 1 }]) {
      const res = await request(app)
        .post('/api/site-report')
        .send({ ...validReport, hostname });
      expect(res.status).toBe(400);
    }
  });

  test('rejects an unknown failure type', async () => {
    const res = await request(app)
      .post('/api/site-report')
      .send({ ...validReport, failureType: 'something_else' });

    expect(res.status).toBe(400);
    expect(mockCollectionRef.add).not.toHaveBeenCalled();
  });

  test('rejects a malformed version', async () => {
    const res = await request(app)
      .post('/api/site-report')
      .send({ ...validReport, version: 'not-a-version' });

    expect(res.status).toBe(400);
  });

  test('ignores extra fields a caller tries to smuggle in', async () => {
    await request(app)
      .post('/api/site-report')
      .send({
        ...validReport,
        username: 'someone@example.com',
        password: 'hunter2',
        url: 'https://example.com/login?session=abc',
      });

    const written = mockCollectionRef.add.mock.calls[0][0];
    expect(Object.keys(written).sort()).toEqual([
      'failureType',
      'hostname',
      'receivedAt',
      'version',
    ]);
  });
});
