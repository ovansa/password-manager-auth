import { Router, Request, Response } from 'express';
import bcrypt from 'bcrypt';
import axios, { HttpStatusCode } from 'axios';
import { db, admin } from '../config/firebase';
import { csrfProtection } from '../middleware/csrf';
import { loginLimiter, registerLimiter, kdfLimiter, tokenLimiter } from '../middleware/rateLimiters';
import { getCurrentTimestamp, validateEmail, sanitizeEmail } from '../helpers/email';
import {
  createFreeLicense,
  hashKey,
  getLicenseForUser,
  getLicensePlanDurationDays,
  isPaidLicensePlan,
  PaidLicensePlan,
  signLicenseForUser,
} from '../helpers/license';
import { logger } from '../helpers/logger';

const router = Router();

// Route: Register new user
router.post('/register', registerLimiter, csrfProtection, async (req: Request, res: Response) => {
  const startMs = Date.now();

  try {
    const { email, passwordHash, kdfIterations, kdfType, licenseKey } = req.body as {
      email?: string;
      passwordHash?: string;
      kdfIterations?: number;
      kdfType?: string;
      licenseKey?: string;
    };

    if (!email || !passwordHash || !kdfIterations || !kdfType) {
      logger.warn('register.missing_fields', { ip: req.ip });
      res.status(400).json({ success: false, error: 'Missing required fields' });
      return;
    }

    const sanitizedEmail = sanitizeEmail(email);
    if (!validateEmail(sanitizedEmail)) {
      logger.warn('register.invalid_email', { ip: req.ip });
      res.status(400).json({ success: false, error: 'Invalid email format' });
      return;
    }

    if (kdfIterations < 600000 || kdfIterations > 2000000) {
      logger.warn('register.invalid_kdf_iterations', { email: sanitizedEmail, kdfIterations });
      res.status(400).json({ success: false, error: 'Invalid KDF iterations' });
      return;
    }

    const VALID_KDF_TYPES = ['pbkdf2-sha256', 'pbkdf2-sha512', 'argon2id'];
    if (!VALID_KDF_TYPES.includes(kdfType)) {
      logger.warn('register.invalid_kdf_type', { email: sanitizedEmail, kdfType });
      res.status(400).json({ success: false, error: 'Invalid KDF type' });
      return;
    }

    const userRef = db.collection('users').doc(sanitizedEmail);
    const userDoc = await userRef.get();

    if (userDoc.exists) {
      logger.warn('register.email_exists', { email: sanitizedEmail });
      res.status(400).json({ success: false, error: 'Registration unsuccessful' });
      return;
    }

    const trimmedLicenseKey = licenseKey?.trim();
    let keyHash: string | null = null;
    let keyData: Record<string, unknown> | null = null;
    let keyPlan: PaidLicensePlan | null = null;

    if (trimmedLicenseKey) {
      keyHash = hashKey(trimmedLicenseKey);
      const keyDoc = await db.collection('license_keys').doc(keyHash).get();

      if (!keyDoc.exists || keyDoc.data()!['revoked']) {
        logger.warn('register.invalid_license', { email: sanitizedEmail });
        res.status(400).json({ success: false, error: 'Invalid license key' });
        return;
      }

      keyData = keyDoc.data()!;
      if (!isPaidLicensePlan(keyData['plan'])) {
        logger.warn('register.invalid_license_plan', { email: sanitizedEmail, plan: keyData['plan'] });
        res.status(400).json({ success: false, error: 'Invalid license key' });
        return;
      }
      keyPlan = keyData['plan'];
      if (
        Number(keyData['use_count'] ?? 0) >= Number(keyData['max_uses'] ?? 1) &&
        keyData['activated_by'] !== sanitizedEmail
      ) {
        logger.warn('register.license_exhausted', { email: sanitizedEmail });
        res.status(400).json({ success: false, error: 'License key has already been used' });
        return;
      }
    }

    const serverHash = await bcrypt.hash(passwordHash, 12);

    const userData = {
      email: sanitizedEmail,
      authHash: serverHash,
      kdfIterations: parseInt(String(kdfIterations)),
      kdfType,
      isSubscribed: !!keyData,
      createdAt: new Date(),
      lastLogin: null,
      isActive: true,
      loginAttempts: 0,
      lockedUntil: null,
    };

    await userRef.set(userData);

    let license = createFreeLicense();

    if (keyData && keyHash && keyPlan) {
      let expires_at: Date | null = null;
      const durationDays =
        keyData['duration_days'] === undefined
          ? getLicensePlanDurationDays(keyPlan)
          : typeof keyData['duration_days'] === 'number'
          ? keyData['duration_days']
          : null;
      if (durationDays) {
        expires_at = new Date(durationDays * 24 * 60 * 60 * 1000 + Date.now());
      }

      const batch = db.batch();

      batch.update(db.collection('license_keys').doc(keyHash), {
        activated_by: sanitizedEmail,
        activated_at: admin.firestore.FieldValue.serverTimestamp(),
        use_count: admin.firestore.FieldValue.increment(1),
      });

      batch.set(db.collection('subscriptions').doc(sanitizedEmail), {
        status: 'active',
        plan: keyPlan,
        expires_at: expires_at ? admin.firestore.Timestamp.fromDate(expires_at) : null,
        activated_at: admin.firestore.FieldValue.serverTimestamp(),
        renewed_at: null,
        key_hash: keyHash,
      });

      batch.set(db.collection('license_activations').doc(), {
        email: sanitizedEmail,
        key_hash: keyHash,
        action: 'activated',
        plan: keyPlan,
        expires_at: expires_at ? admin.firestore.Timestamp.fromDate(expires_at) : null,
        timestamp: admin.firestore.FieldValue.serverTimestamp(),
        ip: req.ip,
      });

      await batch.commit();
      license = {
        status: 'active',
        plan: keyPlan,
        expires_at: expires_at ? expires_at.toISOString() : null,
      };
    }

    logger.info('register.success', {
      email: sanitizedEmail,
      plan: license.plan,
      durationMs: Date.now() - startMs,
    });

    res.status(HttpStatusCode.Created).json({
      success: true,
      message: 'User registered',
      license: signLicenseForUser(sanitizedEmail, license),
    });
  } catch (error) {
    logger.error('register.error', error, { durationMs: Date.now() - startMs });
    res.status(500).json({ success: false, error: 'Registration failed' });
  }
});

// Route: User login
router.post('/login', loginLimiter, csrfProtection, async (req: Request, res: Response) => {
  const startMs = Date.now();

  try {
    const { email, passwordHash } = req.body as { email?: string; passwordHash?: string };

    if (!email || !passwordHash) {
      logger.warn('login.missing_credentials', { ip: req.ip });
      res.status(400).json({ success: false, error: 'Missing credentials' });
      return;
    }

    const sanitizedEmail = sanitizeEmail(email);
    const userRef = db.collection('users').doc(sanitizedEmail);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      await bcrypt.hash('dummy_password', 12); // consistent timing
      logger.warn('login.failed', { ip: req.ip });
      res.status(401).json({ success: false, error: 'Invalid credentials' });
      return;
    }

    const user = userDoc.data()!;

    if (user['lockedUntil'] && new Date() < user['lockedUntil'].toDate()) {
      logger.warn('login.account_locked', {
        email: sanitizedEmail,
        lockedUntil: user['lockedUntil'].toDate().toISOString(),
      });
      res.status(423).json({ success: false, error: 'Account temporarily locked' });
      return;
    }

    const isValidPassword = await bcrypt.compare(passwordHash, user['authHash']);

    if (!isValidPassword) {
      const attempts = (user['loginAttempts'] ?? 0) + 1;
      const updates: Record<string, unknown> = { loginAttempts: attempts };
      if (attempts >= 5) {
        const lockedUntil = new Date(Date.now() + 30 * 60 * 1000);
        updates['lockedUntil'] = lockedUntil;
        logger.warn('login.account_now_locked', {
          email: sanitizedEmail,
          attempts,
          lockedUntil: lockedUntil.toISOString(),
        });
      } else {
        logger.warn('login.failed', { ip: req.ip, attempts });
      }
      await userRef.update(updates);
      res.status(401).json({ success: false, error: 'Invalid credentials' });
      return;
    }

    await userRef.update({ loginAttempts: 0, lockedUntil: null, lastLogin: new Date() });

    logger.info('login.success', { email: sanitizedEmail, durationMs: Date.now() - startMs });

    const license = await getLicenseForUser(sanitizedEmail);

    if (license?.expires_at && new Date(license.expires_at) < new Date()) {
      await db.collection('subscriptions').doc(sanitizedEmail).update({ status: 'expired' });
      license.status = 'expired';
      logger.info('login.license_expired', { email: sanitizedEmail });
    }

    res.json({
      success: true,
      user: {
        email: user['email'],
        kdfIterations: user['kdfIterations'],
        kdfType: user['kdfType'],
      },
      license: signLicenseForUser(sanitizedEmail, license ?? createFreeLicense()),
    });
  } catch (error) {
    logger.error('login.error', error, { durationMs: Date.now() - startMs });
    res.status(500).json({ success: false, error: 'Login failed' });
  }
});

// Route: Get KDF parameters for a user
router.get('/kdf-params', kdfLimiter, async (req: Request, res: Response) => {
  try {
    const { email } = req.query as { email?: string };

    if (!email) {
      res.status(400).json({ error: 'Email required' });
      return;
    }

    const sanitizedEmail = sanitizeEmail(email);
    if (!validateEmail(sanitizedEmail)) {
      res.status(400).json({ error: 'Invalid email format' });
      return;
    }

    const userDoc = await db.collection('users').doc(sanitizedEmail).get();

    if (!userDoc.exists) {
      // Return defaults to prevent user enumeration
      res.json({ iterations: 600000, type: 'pbkdf2-sha256' });
      return;
    }

    const user = userDoc.data()!;
    res.json({ iterations: user['kdfIterations'], type: user['kdfType'] });
  } catch (error) {
    logger.error('kdf_params.error', error);
    res.status(500).json({ error: 'Failed to get parameters' });
  }
});

// Route: Refresh access token
router.post('/refresh', tokenLimiter, async (req: Request, res: Response) => {
  const startMs = Date.now();

  try {
    const { refresh_token } = req.body as { refresh_token?: string };

    const response = await axios.post('https://oauth2.googleapis.com/token', {
      refresh_token,
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      grant_type: 'refresh_token',
    });

    logger.info('token.refresh_success', { durationMs: Date.now() - startMs });

    res.json({
      access_token: response.data.access_token,
      expires_in: response.data.expires_in,
      timestamp: getCurrentTimestamp(),
    });
  } catch (error) {
    logger.error('token.refresh_error', error, { durationMs: Date.now() - startMs });
    res.status(400).json({ error: 'Token refresh failed', timestamp: getCurrentTimestamp() });
  }
});

export default router;
