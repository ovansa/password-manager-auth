import {
  CurrentPaidLicensePlan,
  generateLicenseKey,
  getLicensePlanDurationDays,
  hashKey,
} from '../helpers/license';
import { Request, Response, Router } from 'express';
import { admin, db } from '../config/firebase';
import {
  sanitizeEmail,
  sendLicenseKeyEmail,
  validateEmail,
} from '../helpers/email';

import crypto from 'crypto';
import { logger } from '../helpers/logger';

const router = Router();

type LemonPayload = {
  meta?: {
    event_name?: string;
    custom_data?: Record<string, unknown>;
  };
  data?: {
    id?: string;
    type?: string;
    attributes?: Record<string, unknown>;
  };
};

const PLAN_VARIANT_ENV: Record<CurrentPaidLicensePlan, string[]> = {
  trial_1d: ['LEMON_VARIANT_TRIAL_1D_ID'],
  trial_2w: ['LEMON_VARIANT_TRIAL_2W_ID'],
  trial_3m: ['LEMON_VARIANT_TRIAL_3M_ID', 'LEMON_VARIANT_LAUNCH_TRIAL_ID'],
  monthly: ['LEMON_VARIANT_MONTHLY_ID'],
  annual: ['LEMON_VARIANT_ANNUAL_ID'],
  biannual: ['LEMON_VARIANT_BIANNUAL_ID'],
  lifetime: ['LEMON_VARIANT_LIFETIME_ID'],
};

const SUBSCRIPTION_EVENTS = new Set([
  'subscription_created',
  'subscription_updated',
  'subscription_payment_success',
  'subscription_payment_recovered',
  'subscription_cancelled',
  'subscription_expired',
  'subscription_payment_failed',
]);

function verifyLemonSignature(
  rawBody: Buffer,
  signatureHeader: string | undefined,
): boolean {
  const secret = process.env.LEMONSQUEEZY_WEBHOOK_SECRET;
  if (!secret || !signatureHeader) return false;

  const digest = Buffer.from(
    crypto.createHmac('sha256', secret).update(rawBody).digest('hex'),
    'utf8',
  );
  const signature = Buffer.from(signatureHeader, 'utf8');

  return (
    digest.length === signature.length &&
    crypto.timingSafeEqual(digest, signature)
  );
}

function variantToPlan(variantId: unknown): CurrentPaidLicensePlan | null {
  const value = String(variantId ?? '');
  if (!value) return null;

  for (const [plan, envNames] of Object.entries(PLAN_VARIANT_ENV)) {
    if (envNames.some((envName) => process.env[envName] === value)) {
      return plan as CurrentPaidLicensePlan;
    }
  }
  return null;
}

function getVariantId(payload: LemonPayload): string | null {
  const attrs = payload.data?.attributes ?? {};
  const direct = attrs['variant_id'];
  if (direct) return String(direct);

  const firstOrderItem = attrs['first_order_item'];
  if (firstOrderItem && typeof firstOrderItem === 'object') {
    const variantId = (firstOrderItem as Record<string, unknown>)['variant_id'];
    if (variantId) return String(variantId);
  }

  return null;
}

function getCustomerEmail(payload: LemonPayload): string | null {
  const customEmail = payload.meta?.custom_data?.['email'];
  const attrs = payload.data?.attributes ?? {};
  const email = customEmail || attrs['user_email'] || attrs['customer_email'];
  if (typeof email !== 'string') return null;
  const sanitized = sanitizeEmail(email);
  return validateEmail(sanitized) ? sanitized : null;
}

function getEventName(req: Request, payload: LemonPayload): string {
  return payload.meta?.event_name || req.get('X-Event-Name') || 'unknown';
}

function toTimestamp(value: unknown): FirebaseFirestore.Timestamp | null {
  if (typeof value !== 'string' || !value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return admin.firestore.Timestamp.fromDate(date);
}

function getSubscriptionExpiry(
  payload: LemonPayload,
  plan: CurrentPaidLicensePlan,
): FirebaseFirestore.Timestamp | null {
  if (plan === 'lifetime') return null;
  const attrs = payload.data?.attributes ?? {};
  return (
    toTimestamp(attrs['renews_at']) ||
    toTimestamp(attrs['ends_at']) ||
    toTimestamp(attrs['trial_ends_at']) ||
    admin.firestore.Timestamp.fromDate(
      new Date(
        Date.now() +
          (getLicensePlanDurationDays(plan) ?? 0) * 24 * 60 * 60 * 1000,
      ),
    )
  );
}

function getLicenseExpiry(
  plan: CurrentPaidLicensePlan,
): FirebaseFirestore.Timestamp | null {
  const duration = getLicensePlanDurationDays(plan);
  if (!duration) return null;
  return admin.firestore.Timestamp.fromDate(
    new Date(Date.now() + duration * 24 * 60 * 60 * 1000),
  );
}

function subscriptionStatus(
  payload: LemonPayload,
  eventName: string,
): 'active' | 'expired' {
  const attrs = payload.data?.attributes ?? {};
  const status = String(attrs['status'] ?? '').toLowerCase();
  if (
    eventName === 'subscription_expired' ||
    status === 'expired' ||
    (status === 'cancelled' && !attrs['ends_at'])
  ) {
    return 'expired';
  }
  if (status === 'past_due' || status === 'unpaid') return 'expired';
  return 'active';
}

router.post('/lemon-squeezy', async (req: Request, res: Response) => {
  const rawBody = Buffer.isBuffer(req.body)
    ? req.body
    : Buffer.from(
        typeof req.body === 'string'
          ? req.body
          : JSON.stringify(req.body ?? {}),
      );

  if (!verifyLemonSignature(rawBody, req.get('X-Signature'))) {
    logger.warn('lemon.webhook_invalid_signature', { ip: req.ip });
    res.status(400).json({ success: false, error: 'Invalid signature' });
    return;
  }

  let payload: LemonPayload;
  try {
    payload = JSON.parse(rawBody.toString('utf8')) as LemonPayload;
  } catch {
    res.status(400).json({ success: false, error: 'Invalid JSON' });
    return;
  }

  const eventName = getEventName(req, payload);
  const objectId = payload.data?.id;
  const objectType = payload.data?.type ?? 'unknown';
  const eventId = `${eventName}:${objectType}:${objectId ?? crypto.createHash('sha256').update(rawBody).digest('hex')}`;
  const variantId = getVariantId(payload);
  const plan = variantToPlan(variantId);
  const email = getCustomerEmail(payload);

  if (!plan || !email) {
    logger.warn('lemon.webhook_ignored', {
      eventName,
      variantId,
      hasEmail: !!email,
    });
    res.json({ success: true, ignored: true });
    return;
  }

  let issuedKey: string | null = null;
  let alreadyProcessed = false;

  try {
    const result = await db.runTransaction(async (tx) => {
      const eventRef = db.collection('webhook_events').doc(eventId);
      const eventDoc = await tx.get(eventRef);
      if (eventDoc.exists)
        return { alreadyProcessed: true, licenseKey: null as string | null };

      const now = admin.firestore.FieldValue.serverTimestamp();
      const attrs = payload.data?.attributes ?? {};
      const sourceId = objectId ?? null;
      const purchaseRef = db.collection('lemon_squeezy_purchases').doc(eventId);

      tx.set(eventRef, {
        provider: 'lemon_squeezy',
        event_name: eventName,
        object_id: sourceId,
        object_type: objectType,
        variant_id: variantId,
        plan,
        email,
        processed_at: now,
      });

      tx.set(purchaseRef, {
        event_name: eventName,
        object_id: sourceId,
        object_type: objectType,
        variant_id: variantId,
        plan,
        email,
        lemon_status: attrs['status'] ?? null,
        created_at: now,
        raw_attributes: attrs,
      });

      const isSubscriptionEvent = SUBSCRIPTION_EVENTS.has(eventName);
      const activeStatus = isSubscriptionEvent
        ? subscriptionStatus(payload, eventName)
        : eventName === 'order_refunded' ||
            attrs['status'] === 'refunded' ||
            attrs['refunded'] === true
          ? 'expired'
          : 'active';

      tx.set(
        db.collection('subscriptions').doc(email),
        {
          status: activeStatus,
          plan,
          expires_at: isSubscriptionEvent
            ? getSubscriptionExpiry(payload, plan)
            : getLicenseExpiry(plan),
          activated_at: now,
          renewed_at: now,
          source: 'lemon_squeezy',
          lemon_event_id: eventId,
          lemon_object_id: sourceId,
          lemon_variant_id: variantId,
        },
        { merge: true },
      );

      if (activeStatus !== 'active') {
        return { alreadyProcessed: false, licenseKey: null };
      }

      const licenseKey = generateLicenseKey();
      const keyHash = hashKey(licenseKey);
      tx.set(db.collection('license_keys').doc(keyHash), {
        plan,
        duration_days: getLicensePlanDurationDays(plan),
        max_uses: 1,
        use_count: 0,
        revoked: false,
        activated_by: null,
        created_at: now,
        notes: `Lemon Squeezy ${eventName} ${sourceId ?? ''}`.trim(),
        source: 'lemon_squeezy',
        source_event_id: eventId,
        purchaser_email: email,
      });

      return { alreadyProcessed: false, licenseKey };
    });

    alreadyProcessed = result.alreadyProcessed;
    issuedKey = result.licenseKey;

    if (issuedKey) {
      const emailResult = await sendLicenseKeyEmail({
        email,
        licenseKey: issuedKey,
        plan,
      });
      await db
        .collection('webhook_events')
        .doc(eventId)
        .update({
          email_sent: emailResult.sent,
          email_skipped: !!emailResult.skipped,
          email_error: emailResult.error ?? null,
        });
    }

    logger.info('lemon.webhook_processed', {
      eventName,
      plan,
      email,
      alreadyProcessed,
      issuedKey: !!issuedKey,
    });
    res.json({ success: true, alreadyProcessed });
  } catch (error) {
    logger.error('lemon.webhook_error', error, { eventName, email, plan });
    res
      .status(500)
      .json({ success: false, error: 'Webhook processing failed' });
  }
});

export default router;
