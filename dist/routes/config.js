"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const router = (0, express_1.Router)();
// To enable observability: set observabilityEnabled to true here and
// set OBSERVABILITY_ENABLED = true in src/shared/observability.ts.
// The extension re-fetches this every hour and caches the result.
router.get('/', (_req, res) => {
    res.json({
        observabilityEnabled: false, // ← flip to true to activate
    });
});
exports.default = router;
