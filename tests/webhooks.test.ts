import crypto from 'crypto';
import request from 'supertest';

jest.mock('../src/helpers/email', () => ({
  ...jest.requireActual('../src/helpers/email'),
  sendLicenseKeyEmail: jest.fn().mockResolvedValue({ sent: false, skipped: true }),
}));

import { app } from '../src/app';
import { sendLicenseKeyEmail } from '../src/helpers/email';
import { getMocks } from './getMocks';

const { makeDoc, mockDocRef, mockCollectionRef, mockTransaction, mockDb } =
  getMocks();
const mockSendLicenseKeyEmail = jest.mocked(sendLicenseKeyEmail);

beforeEach(() => {
  jest.clearAllMocks();
  mockSendLicenseKeyEmail.mockResolvedValue({ sent: false, skipped: true });
  mockDocRef.update.mockResolvedValue(undefined);
  mockCollectionRef.doc.mockReturnValue(mockDocRef);
  mockTransaction.get.mockResolvedValue(makeDoc(false));
  mockTransaction.set.mockReturnThis();
  mockDb.runTransaction.mockImplementation(
    async (fn: (tx: typeof mockTransaction) => Promise<unknown>) =>
      fn(mockTransaction),
  );
});

function signedPayload(payload: Record<string, unknown>) {
  const raw = JSON.stringify(payload);
  const signature = crypto
    .createHmac('sha256', process.env.LEMONSQUEEZY_WEBHOOK_SECRET!)
    .update(raw)
    .digest('hex');
  return { raw, signature };
}

describe('POST /api/webhooks/lemon-squeezy', () => {
  test('rejects invalid signatures', async () => {
    const res = await request(app)
      .post('/api/webhooks/lemon-squeezy')
      .set('Content-Type', 'application/json')
      .set('X-Signature', 'bad-signature')
      .send(JSON.stringify({}));

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/invalid signature/i);
  });

  test('processes a lifetime order idempotently and issues a license key', async () => {
    const { raw, signature } = signedPayload({
      meta: {
        event_name: 'order_created',
        custom_data: { email: 'Buyer@Example.com' },
      },
      data: {
        type: 'orders',
        id: 'order-123',
        attributes: {
          status: 'paid',
          first_order_item: {
            variant_id: 'lifetime-variant',
          },
        },
      },
    });

    const res = await request(app)
      .post('/api/webhooks/lemon-squeezy')
      .set('Content-Type', 'application/json')
      .set('X-Signature', signature)
      .send(raw);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(mockTransaction.set).toHaveBeenCalled();
    expect(mockCollectionRef.doc).toHaveBeenCalledWith('buyer@example.com');
    expect(mockSendLicenseKeyEmail).toHaveBeenCalledWith(
      expect.objectContaining({
        email: 'buyer@example.com',
        plan: 'lifetime',
      }),
    );
  });

  test('renewal of an active subscription does not re-issue a key', async () => {
    // First read (webhook_events) -> not processed; second read
    // (subscriptions/{email}) -> already active with a license issued.
    mockTransaction.get
      .mockResolvedValueOnce(makeDoc(false))
      .mockResolvedValueOnce(
        makeDoc(true, { license_issued: true, status: 'active' }),
      );

    const { raw, signature } = signedPayload({
      meta: {
        event_name: 'subscription_payment_success',
        custom_data: { email: 'buyer@example.com' },
      },
      data: {
        type: 'subscriptions',
        id: 'sub-789',
        attributes: {
          status: 'active',
          variant_id: 'annual-variant',
        },
      },
    });

    const res = await request(app)
      .post('/api/webhooks/lemon-squeezy')
      .set('Content-Type', 'application/json')
      .set('X-Signature', signature)
      .send(raw);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    // Expiry still refreshed (subscription doc written), but no new key emailed.
    expect(mockTransaction.set).toHaveBeenCalled();
    expect(mockSendLicenseKeyEmail).not.toHaveBeenCalled();
  });

  test('re-subscribing after a lapse issues a fresh key', async () => {
    // First read (webhook_events) -> not processed; second read
    // (subscriptions/{email}) -> previously issued but now expired.
    mockTransaction.get
      .mockResolvedValueOnce(makeDoc(false))
      .mockResolvedValueOnce(
        makeDoc(true, { license_issued: true, status: 'expired' }),
      );

    const { raw, signature } = signedPayload({
      meta: {
        event_name: 'subscription_created',
        custom_data: { email: 'buyer@example.com' },
      },
      data: {
        type: 'subscriptions',
        id: 'sub-790',
        attributes: {
          status: 'active',
          variant_id: 'annual-variant',
        },
      },
    });

    const res = await request(app)
      .post('/api/webhooks/lemon-squeezy')
      .set('Content-Type', 'application/json')
      .set('X-Signature', signature)
      .send(raw);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(mockSendLicenseKeyEmail).toHaveBeenCalledWith(
      expect.objectContaining({ email: 'buyer@example.com', plan: 'annual' }),
    );
  });

  test('ignores unknown variants without failing Lemon retries', async () => {
    const { raw, signature } = signedPayload({
      meta: { event_name: 'order_created' },
      data: {
        type: 'orders',
        id: 'order-456',
        attributes: {
          user_email: 'buyer@example.com',
          first_order_item: { variant_id: 'unknown-variant' },
        },
      },
    });

    const res = await request(app)
      .post('/api/webhooks/lemon-squeezy')
      .set('Content-Type', 'application/json')
      .set('X-Signature', signature)
      .send(raw);

    expect(res.status).toBe(200);
    expect(res.body.ignored).toBe(true);
  });
});
