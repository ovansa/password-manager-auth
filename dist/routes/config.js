"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const license_1 = require("../helpers/license");
const router = (0, express_1.Router)();
// To enable observability: set observabilityEnabled to true here and
// set OBSERVABILITY_ENABLED = true in src/shared/observability.ts.
// The extension re-fetches this every hour and caches the result.
router.get('/', (_req, res) => {
    res.json({
        observabilityEnabled: false, // ← flip to true to activate
        licensePublicKey: (0, license_1.getLicensePublicKeyPem)(),
        licensePolicy: license_1.DEFAULT_LICENSE_POLICY,
    });
});
exports.default = router;
