import { Router, Request, Response } from 'express';
import { db, admin } from '../config/firebase';
import { csrfProtection } from '../middleware/csrf';
import { licenseLimiter } from '../middleware/rateLimiters';
import { sanitizeEmail } from '../helpers/email';
import {
  createFreeLicense,
  hashKey,
  checkSubscriptionStatus,
  getLicensePlanDurationDays,
  getLicenseForUser,
  isPaidLicensePlan,
  signLicenseForUser,
} from '../helpers/license';
import { logger } from '../helpers/logger';

const router = Router();

// Route: Activate a license key against a user account
router.post('/activate', licenseLimiter, csrfProtection, async (req: Request, res: Response) => {
  try {
    const { email, key } = req.body as { email?: string; key?: string };
    if (!email || !key) {
      res.status(400).json({ success: false, error: 'Missing email or key' });
      return;
    }

    const sanitizedEmail = sanitizeEmail(email);
    const keyHash = hashKey(key);
    const keyRef = db.collection('license_keys').doc(keyHash);

    // Run in a transaction so concurrent activations can't exceed max_uses
    const result = await db.runTransaction(async (tx) => {
      const keyDoc = await tx.get(keyRef);

      if (!keyDoc.exists) return { success: false, error: 'Invalid license key' };

      const keyData = keyDoc.data()!;
      if (!isPaidLicensePlan(keyData['plan'])) {
        return { success: false, error: 'Invalid license key' };
      }
      const keyPlan = keyData['plan'];

      if (keyData['revoked']) {
        return { success: false, error: 'This license key has been revoked' };
      }

      if (keyData['use_count'] >= keyData['max_uses']) {
        if (keyData['activated_by'] !== sanitizedEmail) {
          return { success: false, error: 'This license key has already been used' };
        }
      }

      let expires_at: Date | null = null;
      const durationDays =
        keyData['duration_days'] === undefined
          ? getLicensePlanDurationDays(keyPlan)
          : typeof keyData['duration_days'] === 'number'
          ? keyData['duration_days']
          : null;
      if (durationDays) {
        expires_at = new Date(Date.now() + durationDays * 24 * 60 * 60 * 1000);
      }

      const isReactivation = keyData['activated_by'] === sanitizedEmail;

      tx.update(keyRef, {
        activated_by: sanitizedEmail,
        activated_at: admin.firestore.FieldValue.serverTimestamp(),
        use_count: isReactivation
          ? keyData['use_count']
          : admin.firestore.FieldValue.increment(1),
      });

      const subRef = db.collection('subscriptions').doc(sanitizedEmail);
      tx.set(subRef, {
        status: 'active',
        plan: keyPlan,
        expires_at: expires_at ? admin.firestore.Timestamp.fromDate(expires_at) : null,
        activated_at: admin.firestore.FieldValue.serverTimestamp(),
        renewed_at: isReactivation ? admin.firestore.FieldValue.serverTimestamp() : null,
        key_hash: keyHash,
      });

      const logRef = db.collection('license_activations').doc();
      tx.set(logRef, {
        email: sanitizedEmail,
        key_hash: keyHash,
        action: isReactivation ? 'renewed' : 'activated',
        plan: keyPlan,
        expires_at: expires_at ? admin.firestore.Timestamp.fromDate(expires_at) : null,
        timestamp: admin.firestore.FieldValue.serverTimestamp(),
        ip: req.ip,
      });

      return {
        success: true,
        plan: keyPlan,
        expires_at: expires_at ? expires_at.toISOString() : null,
      };
    });

    if (!result.success) {
      logger.warn('license.activate_rejected', { email: sanitizedEmail, reason: result.error });
      res.status(400).json(result);
      return;
    }

    logger.info('license.activated', { email: sanitizedEmail, plan: result.plan });
    res.json({
      ...result,
      license: signLicenseForUser(sanitizedEmail, {
        status: 'active',
        plan: result.plan ?? null,
        expires_at: result.expires_at ?? null,
      }),
    });
  } catch (error) {
    logger.error('license.activate_error', error);
    res.status(500).json({ success: false, error: 'Activation failed' });
  }
});

// Route: Revalidate current entitlement and return a freshly signed payload
router.post('/validate', licenseLimiter, csrfProtection, async (req: Request, res: Response) => {
  try {
    const { email } = req.body as { email?: string };
    if (!email) {
      res.status(400).json({ success: false, error: 'Missing email' });
      return;
    }

    const sanitizedEmail = sanitizeEmail(email);
    const license = await getLicenseForUser(sanitizedEmail);

    if (license?.expires_at && new Date(license.expires_at) < new Date()) {
      await db.collection('subscriptions').doc(sanitizedEmail).update({ status: 'expired' });
      license.status = 'expired';
    }

    res.json({
      success: true,
      license: signLicenseForUser(sanitizedEmail, license ?? createFreeLicense()),
    });
  } catch (error) {
    logger.error('license.validate_error', error);
    res.status(500).json({ success: false, error: 'Validation failed' });
  }
});

// Route: Check subscription eligibility
router.post('/check-eligibility', licenseLimiter, csrfProtection, async (req: Request, res: Response) => {
  try {
    const { email } = req.body as { email?: string };
    if (!email) {
      res.status(400).json({ eligible: false });
      return;
    }

    const sanitizedEmail = sanitizeEmail(email);
    const hasSubscription = await checkSubscriptionStatus(sanitizedEmail);
    res.json({ eligible: hasSubscription });
  } catch (error) {
    logger.error('subscription.check_error', error);
    res.status(500).json({ eligible: false });
  }
});

export default router;
