import { Router, Request, Response } from 'express';
import { db } from '../config/firebase';
import { analyticsLimiter } from '../middleware/rateLimiters';
import { logger } from '../helpers/logger';

const router = Router();

// Allowlist of valid event names - rejects anything unexpected
const VALID_EVENTS = new Set([
  'vault_created',
  'vault_unlocked',
  'vault_locked',
  'autofill_triggered',
  'autofill_succeeded',
  'password_saved',
  'password_deleted',
  'password_generated',
  'sync_succeeded',
  'sync_failed',
  'export_completed',
  'import_completed',
  'license_activated',
  'license_validation_failed',
]);

router.post('/event', analyticsLimiter, async (req: Request, res: Response) => {
  try {
    const {
      event,
      installId,
      meta = {},
      ts,
    } = req.body as {
      event: string;
      installId: string;
      meta?: Record<string, unknown>;
      ts?: string;
    };

    if (!event || !VALID_EVENTS.has(event)) {
      res.status(400).json({ error: 'Invalid event' });
      return;
    }

    const uuidRegex =
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    if (!installId || !uuidRegex.test(installId)) {
      res.status(400).json({ error: 'Invalid installId' });
      return;
    }

    // Scrub meta - only allow primitive values, no nested objects
    const safeMeta: Record<string, string | number | boolean> = {};
    for (const [key, value] of Object.entries(meta)) {
      if (['string', 'number', 'boolean'].includes(typeof value)) {
        safeMeta[key] = value as string | number | boolean;
      }
    }

    await db.collection('analytics').add({
      event,
      installId,
      meta: safeMeta,
      ts: ts ? new Date(ts) : new Date(),
      receivedAt: new Date(),
    });

    res.json({ ok: true });
  } catch (error) {
    logger.error('analytics.event_error', error, { event: req.body?.event });
    // Always return 200 - analytics failures should never surface to the extension
    res.json({ ok: false });
  }
});

export default router;
