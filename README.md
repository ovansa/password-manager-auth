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

### Getting Firebase Admin credentials

1. Go to **Firebase Console → Project Settings → Service accounts**
2. Click **Generate new private key** → download the JSON file
3. From the downloaded JSON, copy these three values into Render environment variables:
   - `FIREBASE_PROJECT_ID` → `project_id` field
   - `FIREBASE_CLIENT_EMAIL` → `client_email` field
   - `FIREBASE_PRIVATE_KEY` → `private_key` field (paste as-is, including all `\n` characters)

> **Note**: The server uses **Firebase Admin SDK** which bypasses Firestore security rules. This is the correct approach for server-side code. No Firestore rule changes are needed.

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/api/auth/register` | CSRF | Register new user |
| `POST` | `/api/auth/login` | CSRF | Login and verify credentials |
| `GET` | `/api/auth/kdf-params` | None | Get key derivation parameters for a user |
| `POST` | `/api/subscription/check-eligibility` | None | Check subscription status |
| `POST` | `/api/auth/google` | None | Exchange Google OAuth code for tokens |
| `POST` | `/api/auth/refresh` | None | Refresh Google access token |

> **CSRF protection**: `/register` and `/login` require the `X-Requested-With: XMLHttpRequest` header.
