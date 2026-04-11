import { Router, Request, Response } from 'express';

const router = Router();

// To enable observability: set observabilityEnabled to true here and
// set OBSERVABILITY_ENABLED = true in src/shared/observability.ts.
// The extension re-fetches this every hour and caches the result.
router.get('/', (_req: Request, res: Response) => {
  res.json({
    observabilityEnabled: false, // ← flip to true to activate
  });
});

export default router;
