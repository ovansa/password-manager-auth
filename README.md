# password-manager-auth

Express server providing authentication for the Passa browser extension. Uses Firebase Firestore for user storage.

## Setup

```bash
pnpm install
cp .env.example .env   # fill in your values
pnpm dev
```

## Environment Variables

**These must be added manually in the Render dashboard** (the `.env` file is gitignored and never deployed).

| Variable | Where to get it |
|----------|----------------|
| `FIREBASE_PROJECT_ID` | Firebase Console → Project Settings → Service accounts → your project ID |
| `FIREBASE_CLIENT_EMAIL` | Firebase Console → Project Settings → Service accounts → Generate new private key → `client_email` field |
| `FIREBASE_PRIVATE_KEY` | Same JSON → `private_key` field. Paste the full value including `-----BEGIN...` and `-----END...` lines |
| `GOOGLE_CLIENT_ID` | Google Cloud Console → OAuth 2.0 credentials |
| `GOOGLE_CLIENT_SECRET` | Same |
| `FRONTEND_URL` | Your deployed frontend origin (used for CORS in production) |
| `LICENSE_SIGNING_PRIVATE_KEY` | RSA private key used to sign extension license payloads. Required in production |
| `LICENSE_SIGNING_PUBLIC_KEY` | Optional RSA public key to expose from `/api/config`; if omitted, it is derived from the private key |
| `LICENSE_SIGNING_KEY_ID` | Optional key ID included in signed license token headers |

### Getting Firebase Admin credentials

1. Go to **Firebase Console → Project Settings → Service accounts**
2. Click **Generate new private key** → download the JSON file
3. From the downloaded JSON, copy these three values into Render environment variables:
   - `FIREBASE_PROJECT_ID` → `project_id` field
   - `FIREBASE_CLIENT_EMAIL` → `client_email` field
   - `FIREBASE_PRIVATE_KEY` → `private_key` field (paste as-is, including all `\n` characters)

> **Note**: The server uses **Firebase Admin SDK** which bypasses Firestore security rules. This is the correct approach for server-side code. No Firestore rule changes are needed.

### License signing key

Production must set `LICENSE_SIGNING_PRIVATE_KEY`; otherwise the server refuses to start license signing. Development and tests generate an ephemeral key pair automatically.

Generate a production key pair with OpenSSL:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out license-private.pem
openssl rsa -pubout -in license-private.pem -out license-public.pem
```

Paste the private key into `LICENSE_SIGNING_PRIVATE_KEY` exactly as PEM text. `LICENSE_SIGNING_PUBLIC_KEY` is optional, but setting it explicitly makes key rotation easier to reason about because `/api/config` serves that public key to the extension.

### License plans

Paid plans are defined in `src/helpers/license.ts` and reused by the key-generation and migration scripts.

| Plan | Duration | Intended use |
|------|----------|--------------|
| `trial_1d` | 1 day | Internal testing |
| `trial_2w` | 14 days | Short trial |
| `trial_3m` | 90 days | First-500 early access offer |
| `monthly` | 30 days | Monthly Pro |
| `annual` | 365 days | Annual Pro |
| `biannual` | 180 days | Legacy/semiannual Pro |
| `lifetime` | No expiry | Lifetime Pro |

`pro` remains accepted as a legacy paid plan for older subscription records, but new generated keys should use the explicit plans above.

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/api/auth/register` | CSRF | Register new user |
| `POST` | `/api/auth/login` | CSRF | Login and verify credentials |
| `GET` | `/api/auth/kdf-params` | None | Get key derivation parameters for a user |
| `POST` | `/api/license/activate` | CSRF | Activate a license key and return a signed entitlement |
| `POST` | `/api/license/validate` | CSRF | Refresh the signed entitlement for a user |
| `GET` | `/api/config` | None | Return public runtime config including license public key and policy |
| `POST` | `/api/subscription/check-eligibility` | None | Check subscription status |
| `POST` | `/api/auth/google` | None | Exchange Google OAuth code for tokens |
| `POST` | `/api/auth/refresh` | None | Refresh Google access token |

> **CSRF protection**: `/register` and `/login` require the `X-Requested-With: XMLHttpRequest` header.
