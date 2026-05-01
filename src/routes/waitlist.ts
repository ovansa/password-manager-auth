import { Router, Request, Response } from 'express';
import { db, admin } from '../config/firebase';
import { generalLimiter } from '../middleware/rateLimiters';
import { sanitizeEmail, validateEmail } from '../helpers/email';
import { logger } from '../helpers/logger';

const router = Router();

router.post('/', generalLimiter, async (req: Request, res: Response) => {
  try {
    const email = sanitizeEmail(String(req.body?.email ?? ''));
    if (!validateEmail(email)) {
      res.status(400).json({ error: 'Please enter a valid email address.' });
      return;
    }

    await db.collection('waitlist').doc(email).set(
      {
        email,
        source: req.body?.source ?? 'website',
        updated_at: admin.firestore.FieldValue.serverTimestamp(),
        created_at: admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true },
    );

    logger.info('waitlist.signup', { email });
    res.status(201).json({
      message: "You're on the list! We'll send details for the 3-month Pro launch offer.",
    });
  } catch (error) {
    logger.error('waitlist.error', error);
    res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});

export default router;
