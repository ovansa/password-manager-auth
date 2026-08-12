import { Router, Request, Response } from 'express';
import { db } from '../config/firebase';
import { siteReportLimiter } from '../middleware/rateLimiters';
import { logger } from '../helpers/logger';

const router = Router();

/**
 * Broken-site reports from the extension.
 *
 * Accepts a hostname, the extension version and which step failed — nothing
 * else. No full URL, no path or query string, no form data, no credentials,
 * no install id. The extension shows the user exactly this payload before
 * sending. Keep it that way: anything richer turns a support channel into a
 * browsing-history feed.
 */

const VALID_FAILURE_TYPES = new Set([
  'no_button',
  'wrong_field',
  'save_prompt_missing',
  'fill_did_not_stick',
]);

// Hostnames only: labels, dots, optional port-free punycode. Rejects anything
// carrying a scheme, path, credentials or query string.
const HOSTNAME_RE =
  /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$/;

const VERSION_RE = /^\d{1,3}(\.\d{1,5}){0,3}$/;

router.post('/', siteReportLimiter, async (req: Request, res: Response) => {
  try {
    const { hostname, version, failureType } = req.body as {
      hostname?: unknown;
      version?: unknown;
      failureType?: unknown;
    };

    if (typeof hostname !== 'string') {
      res.status(400).json({ error: 'Invalid hostname' });
      return;
    }

    const normalizedHost = hostname.trim().toLowerCase();
    if (!normalizedHost || !HOSTNAME_RE.test(normalizedHost)) {
      res.status(400).json({ error: 'Invalid hostname' });
      return;
    }

    if (typeof version !== 'string' || !VERSION_RE.test(version.trim())) {
      res.status(400).json({ error: 'Invalid version' });
      return;
    }

    if (
      typeof failureType !== 'string' ||
      !VALID_FAILURE_TYPES.has(failureType)
    ) {
      res.status(400).json({ error: 'Invalid failureType' });
      return;
    }

    await db.collection('siteReports').add({
      hostname: normalizedHost,
      version: version.trim(),
      failureType,
      // Server-side timestamp only: a client-supplied one adds nothing and
      // can be spoofed.
      receivedAt: new Date(),
    });

    res.json({ ok: true });
  } catch (error) {
    logger.error('siteReport.error', error);
    res.status(500).json({ error: 'Could not record report' });
  }
});

export default router;
