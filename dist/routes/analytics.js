'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const express_1 = require('express');
const firebase_1 = require('../config/firebase');
const rateLimiters_1 = require('../middleware/rateLimiters');
const router = (0, express_1.Router)();
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
router.post('/event', rateLimiters_1.analyticsLimiter, async (req, res) => {
  try {
    const { event, installId, meta = {}, ts } = req.body;
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
    const safeMeta = {};
    for (const [key, value] of Object.entries(meta)) {
      if (['string', 'number', 'boolean'].includes(typeof value)) {
        safeMeta[key] = value;
      }
    }
    await firebase_1.db.collection('analytics').add({
      event,
      installId,
      meta: safeMeta,
      ts: ts ? new Date(ts) : new Date(),
      receivedAt: new Date(),
    });
    res.json({ ok: true });
  } catch (error) {
    console.error('Analytics error:', error.message);
    // Always return 200 - analytics failures should never surface to the extension
    res.json({ ok: false });
  }
});
exports.default = router;
