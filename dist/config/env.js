"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateStartupEnv = validateStartupEnv;
exports.getRequiredEnv = getRequiredEnv;
const logger_1 = require("../helpers/logger");
const REQUIRED_IN_ALL_ENVS = [
    'FIREBASE_PROJECT_ID',
    'FIREBASE_CLIENT_EMAIL',
    'FIREBASE_PRIVATE_KEY',
    'SERVER_URL',
    'GOOGLE_CLIENT_ID',
    'GOOGLE_CLIENT_SECRET',
];
const REQUIRED_IN_PRODUCTION = [
    'FRONTEND_URL',
    'LICENSE_SIGNING_PRIVATE_KEY',
    'LEMONSQUEEZY_WEBHOOK_SECRET',
    'RESEND_API_KEY',
    'TRANSACTIONAL_EMAIL_FROM',
];
const VARIANT_ENV_NAMES = [
    'LEMON_VARIANT_TRIAL_1D_ID',
    'LEMON_VARIANT_TRIAL_2W_ID',
    'LEMON_VARIANT_TRIAL_3M_ID',
    'LEMON_VARIANT_LAUNCH_TRIAL_ID',
    'LEMON_VARIANT_MONTHLY_ID',
    'LEMON_VARIANT_ANNUAL_ID',
    'LEMON_VARIANT_BIANNUAL_ID',
    'LEMON_VARIANT_LIFETIME_ID',
];
function isMissing(value) {
    return !value || !value.trim();
}
function findMissing(names) {
    return names.filter((name) => isMissing(process.env[name]));
}
function hasAnyVariantConfigured() {
    return VARIANT_ENV_NAMES.some((name) => !isMissing(process.env[name]));
}
function validateStartupEnv() {
    const missing = findMissing(REQUIRED_IN_ALL_ENVS);
    const env = process.env.NODE_ENV ?? 'development';
    const isProd = env === 'production';
    const isTest = env === 'test';
    if (isProd) {
        missing.push(...findMissing(REQUIRED_IN_PRODUCTION));
        if (!hasAnyVariantConfigured()) {
            missing.push('One of: ' + VARIANT_ENV_NAMES.join(', '));
        }
    }
    else if (!isTest) {
        if (isMissing(process.env.RESEND_API_KEY)) {
            logger_1.logger.warn('startup.email_delivery_disabled', {
                reason: 'RESEND_API_KEY missing',
            });
        }
        if (!hasAnyVariantConfigured()) {
            logger_1.logger.warn('startup.webhook_variants_unconfigured', {
                vars: VARIANT_ENV_NAMES.join(', '),
            });
        }
    }
    if (missing.length > 0) {
        logger_1.logger.fatal('startup.missing_env', { vars: missing.join(', ') });
        process.exit(1);
    }
}
function getRequiredEnv(name) {
    const value = process.env[name]?.trim();
    if (!value) {
        throw new Error(`Missing required environment variable: ${name}`);
    }
    return value;
}
