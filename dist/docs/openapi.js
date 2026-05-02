"use strict";
/**
 * OpenAPI 3.0 spec for the Passa auth API.
 * Loaded only in non-production environments via /docs.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.openApiSpec = void 0;
exports.openApiSpec = {
    openapi: '3.0.3',
    info: {
        title: 'Passa Auth API',
        version: '1.0.0',
        description: 'Authentication, OAuth relay, license activation, and analytics endpoints for the Passa password manager extension.',
    },
    servers: [
        { url: 'http://localhost:3000', description: 'Local dev' },
    ],
    tags: [
        { name: 'Auth', description: 'Registration, login, token refresh, KDF params' },
        { name: 'OAuth', description: 'Google OAuth relay' },
        { name: 'License', description: 'License key activation and subscription checks' },
        { name: 'Analytics', description: 'Anonymous client telemetry' },
        { name: 'Config', description: 'Public client config' },
    ],
    components: {
        securitySchemes: {
            csrf: {
                type: 'apiKey',
                in: 'header',
                name: 'X-Requested-With',
                description: "Must be set to 'XMLHttpRequest' on state-changing requests.",
            },
        },
        schemas: {
            Error: {
                type: 'object',
                properties: { error: { type: 'string' } },
            },
            License: {
                type: 'object',
                properties: {
                    status: { type: 'string', enum: ['active', 'expired', 'none'] },
                    plan: { type: 'string', nullable: true },
                    expires_at: { type: 'string', format: 'date-time', nullable: true },
                },
            },
        },
    },
    paths: {
        '/api/auth/register': {
            post: {
                tags: ['Auth'],
                summary: 'Register a new user',
                security: [{ csrf: [] }],
                requestBody: {
                    required: true,
                    content: {
                        'application/json': {
                            schema: {
                                type: 'object',
                                required: ['email', 'passwordHash', 'kdfIterations', 'kdfType'],
                                properties: {
                                    email: { type: 'string', format: 'email' },
                                    passwordHash: { type: 'string', description: 'Client-side derived hash' },
                                    kdfIterations: { type: 'integer', minimum: 600000, maximum: 2000000 },
                                    kdfType: { type: 'string', enum: ['pbkdf2-sha256', 'pbkdf2-sha512', 'argon2id'] },
                                    licenseKey: { type: 'string', description: 'Optional paid license key' },
                                },
                            },
                        },
                    },
                },
                responses: {
                    201: { description: 'User created' },
                    400: { description: 'Validation or license error', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
                    429: { description: 'Rate limited' },
                },
            },
        },
        '/api/auth/login': {
            post: {
                tags: ['Auth'],
                summary: 'Log in a user',
                security: [{ csrf: [] }],
                requestBody: {
                    required: true,
                    content: {
                        'application/json': {
                            schema: {
                                type: 'object',
                                required: ['email', 'passwordHash'],
                                properties: {
                                    email: { type: 'string', format: 'email' },
                                    passwordHash: { type: 'string' },
                                },
                            },
                        },
                    },
                },
                responses: {
                    200: { description: 'Login success — returns user + license' },
                    401: { description: 'Invalid credentials' },
                    423: { description: 'Account temporarily locked' },
                    429: { description: 'Rate limited' },
                },
            },
        },
        '/api/auth/kdf-params': {
            get: {
                tags: ['Auth'],
                summary: 'Get KDF parameters for an email (returns defaults if user not found)',
                parameters: [
                    { name: 'email', in: 'query', required: true, schema: { type: 'string', format: 'email' } },
                ],
                responses: {
                    200: {
                        description: 'KDF params',
                        content: {
                            'application/json': {
                                schema: {
                                    type: 'object',
                                    properties: {
                                        iterations: { type: 'integer' },
                                        type: { type: 'string' },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        '/api/auth/refresh': {
            post: {
                tags: ['Auth'],
                summary: 'Refresh a Google access token',
                requestBody: {
                    required: true,
                    content: {
                        'application/json': {
                            schema: {
                                type: 'object',
                                required: ['refresh_token'],
                                properties: { refresh_token: { type: 'string' } },
                            },
                        },
                    },
                },
                responses: {
                    200: { description: 'New access token' },
                    400: { description: 'Refresh failed' },
                },
            },
        },
        '/api/auth/google/callback': {
            get: {
                tags: ['OAuth'],
                summary: 'Google redirects here after consent (HTML response)',
                parameters: [
                    { name: 'code', in: 'query', schema: { type: 'string' } },
                    { name: 'state', in: 'query', schema: { type: 'string' } },
                    { name: 'error', in: 'query', schema: { type: 'string' } },
                ],
                responses: {
                    200: { description: 'Success page (HTML)' },
                    400: { description: 'Failure page (HTML)' },
                },
            },
        },
        '/api/auth/google/code': {
            get: {
                tags: ['OAuth'],
                summary: 'Extension polls for the relayed auth code (one-time use)',
                parameters: [
                    { name: 'state', in: 'query', required: true, schema: { type: 'string' } },
                ],
                responses: {
                    200: { description: 'Code retrieved' },
                    404: { description: 'Pending — code not yet received' },
                    410: { description: 'Code expired' },
                },
            },
        },
        '/api/auth/google/redirect-uri': {
            get: {
                tags: ['OAuth'],
                summary: 'Returns the relay redirect URI registered with Google',
                responses: { 200: { description: 'redirect_uri' } },
            },
        },
        '/api/auth/google': {
            post: {
                tags: ['OAuth'],
                summary: 'Exchange auth code for Google tokens',
                requestBody: {
                    required: true,
                    content: {
                        'application/json': {
                            schema: {
                                type: 'object',
                                required: ['code', 'redirect_uri', 'code_verifier'],
                                properties: {
                                    code: { type: 'string' },
                                    redirect_uri: { type: 'string' },
                                    code_verifier: { type: 'string', description: 'PKCE verifier' },
                                },
                            },
                        },
                    },
                },
                responses: {
                    200: { description: 'Tokens returned' },
                    400: { description: 'Authentication failed' },
                },
            },
        },
        '/api/license/activate': {
            post: {
                tags: ['License'],
                summary: 'Activate a license key against an account',
                security: [{ csrf: [] }],
                requestBody: {
                    required: true,
                    content: {
                        'application/json': {
                            schema: {
                                type: 'object',
                                required: ['email', 'key'],
                                properties: {
                                    email: { type: 'string', format: 'email' },
                                    key: { type: 'string' },
                                },
                            },
                        },
                    },
                },
                responses: {
                    200: { description: 'License activated' },
                    400: { description: 'Invalid / revoked / used' },
                },
            },
        },
        '/api/subscription/check-eligibility': {
            post: {
                tags: ['License'],
                summary: 'Check whether an email currently has an active subscription',
                requestBody: {
                    required: true,
                    content: {
                        'application/json': {
                            schema: {
                                type: 'object',
                                required: ['email'],
                                properties: { email: { type: 'string', format: 'email' } },
                            },
                        },
                    },
                },
                responses: {
                    200: {
                        description: 'Eligibility result',
                        content: {
                            'application/json': {
                                schema: { type: 'object', properties: { eligible: { type: 'boolean' } } },
                            },
                        },
                    },
                },
            },
        },
        '/api/analytics/event': {
            post: {
                tags: ['Analytics'],
                summary: 'Record an anonymous client event',
                requestBody: {
                    required: true,
                    content: {
                        'application/json': {
                            schema: {
                                type: 'object',
                                required: ['event', 'installId'],
                                properties: {
                                    event: {
                                        type: 'string',
                                        enum: [
                                            'vault_created', 'vault_unlocked', 'vault_locked',
                                            'autofill_triggered', 'autofill_succeeded',
                                            'password_saved', 'password_deleted', 'password_generated',
                                            'sync_succeeded', 'sync_failed',
                                            'export_completed', 'import_completed',
                                            'license_activated', 'license_validation_failed',
                                        ],
                                    },
                                    installId: { type: 'string', format: 'uuid' },
                                    meta: { type: 'object', description: 'Primitive values only — nested objects are stripped' },
                                    ts: { type: 'string', format: 'date-time' },
                                },
                            },
                        },
                    },
                },
                responses: {
                    200: { description: 'Always 200 — { ok: true } on success, { ok: false } on storage failure' },
                    400: { description: 'Invalid event or installId' },
                },
            },
        },
        '/api/config': {
            get: {
                tags: ['Config'],
                summary: 'Public client config flags',
                responses: {
                    200: {
                        description: 'Config',
                        content: {
                            'application/json': {
                                schema: {
                                    type: 'object',
                                    properties: { observabilityEnabled: { type: 'boolean' } },
                                },
                            },
                        },
                    },
                },
            },
        },
    },
};
