import crypto from 'crypto';
import { db } from '../config/firebase';

const LICENSE_TOKEN_VERSION = 1;

export const LICENSE_PLAN_DURATIONS_DAYS = {
  trial_1d: 1,
  trial_2w: 14,
  trial_3m: 90,
  monthly: 30,
  annual: 365,
  biannual: 180,
  lifetime: null,
} as const;

export type CurrentPaidLicensePlan = keyof typeof LICENSE_PLAN_DURATIONS_DAYS;

export const CURRENT_PAID_LICENSE_PLANS = [
  'trial_1d',
  'trial_2w',
  'trial_3m',
  'monthly',
  'annual',
  'biannual',
  'lifetime',
] as const satisfies readonly CurrentPaidLicensePlan[];

const LEGACY_PAID_PLANS = ['pro'] as const;
export const PAID_LICENSE_PLANS = [
  ...CURRENT_PAID_LICENSE_PLANS,
  ...LEGACY_PAID_PLANS,
] as const;

export type LegacyPaidLicensePlan = (typeof LEGACY_PAID_PLANS)[number];
export type PaidLicensePlan = CurrentPaidLicensePlan | LegacyPaidLicensePlan;
export type LicensePlan = 'free' | PaidLicensePlan;

export interface LicensePayload {
  status: string;
  plan: LicensePlan | null;
  expires_at: string | null;
}

export interface SignedLicensePayload extends LicensePayload {
  sub: string;
  issued_at: string;
  validated_at: string;
  token_version: number;
  token: string;
}

export interface LicensePolicy {
  validationFreshnessHours: number;
  offlineGraceHours: number;
  allowExistingTotpWhenStale: boolean;
  existingTotpGraceHours: number;
}

export const DEFAULT_LICENSE_POLICY: LicensePolicy = {
  validationFreshnessHours: 24,
  offlineGraceHours: 48,
  allowExistingTotpWhenStale: true,
  existingTotpGraceHours: 168,
};

export const hashKey = (key: string): string =>
  crypto.createHash('sha256').update(key.trim().toUpperCase()).digest('hex');

export function isPaidLicensePlan(plan: unknown): plan is PaidLicensePlan {
  return (
    typeof plan === 'string' &&
    (PAID_LICENSE_PLANS as readonly string[]).includes(plan)
  );
}

export function normalizeLicensePlan(plan: unknown): LicensePlan | null {
  if (plan === 'free') return 'free';
  return isPaidLicensePlan(plan) ? plan : null;
}

export function getLicensePlanDurationDays(
  plan: PaidLicensePlan,
): number | null {
  if (plan === 'pro') return null;
  return LICENSE_PLAN_DURATIONS_DAYS[plan as CurrentPaidLicensePlan];
}

const generatedDevKeyPair =
  process.env.NODE_ENV === 'production'
    ? null
    : crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });

function getPrivateKeyPem(): string {
  const envKey = process.env.LICENSE_SIGNING_PRIVATE_KEY?.replace(/\\n/g, '\n');
  if (envKey) return envKey;
  if (generatedDevKeyPair) return generatedDevKeyPair.privateKey;
  throw new Error('LICENSE_SIGNING_PRIVATE_KEY is required in production');
}

export function getLicensePublicKeyPem(): string {
  const envPublicKey = process.env.LICENSE_SIGNING_PUBLIC_KEY?.replace(/\\n/g, '\n');
  if (envPublicKey) return envPublicKey;

  if (generatedDevKeyPair) return generatedDevKeyPair.publicKey;

  return crypto
    .createPublicKey(getPrivateKeyPem())
    .export({ type: 'spki', format: 'pem' })
    .toString();
}

function base64UrlEncode(input: string | Buffer): string {
  return Buffer.from(input)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function signPayload(payload: Record<string, unknown>): string {
  const header = {
    alg: 'RS256',
    typ: 'JWT',
    kid: process.env.LICENSE_SIGNING_KEY_ID ?? 'passa-license-v1',
  };
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(signingInput);
  signer.end();
  const signature = signer.sign(getPrivateKeyPem());
  return `${signingInput}.${base64UrlEncode(signature)}`;
}

export function createFreeLicense(): LicensePayload {
  return { status: 'free', plan: 'free', expires_at: null };
}

export function signLicenseForUser(
  email: string,
  license: LicensePayload | null,
): SignedLicensePayload {
  const now = new Date().toISOString();
  const payload = {
    sub: email,
    status: license?.status ?? 'free',
    plan: normalizeLicensePlan(license?.plan) ?? 'free',
    expires_at: license?.expires_at ?? null,
    issued_at: now,
    validated_at: now,
    token_version: LICENSE_TOKEN_VERSION,
  };

  return {
    ...payload,
    token: signPayload(payload),
  };
}

/**
 * Read subscriptions/{email} and return a license payload for the client.
 * Returns null if no subscription exists.
 */
export async function getLicenseForUser(email: string): Promise<LicensePayload | null> {
  const subDoc = await db.collection('subscriptions').doc(email).get();
  if (!subDoc.exists) return null;
  const sub = subDoc.data()!;
  return {
    status: sub['status'],
    plan: normalizeLicensePlan(sub['plan']),
    expires_at: sub['expires_at'] ? sub['expires_at'].toDate().toISOString() : null,
  };
}

/**
 * Check if user has a valid (active) subscription.
 */
export async function checkSubscriptionStatus(email: string): Promise<boolean> {
  try {
    const userDoc = await db.collection('users').doc(email).get();
    if (userDoc.exists) {
      return userDoc.data()!['isSubscribed'] === true;
    }
    return false;
  } catch (error) {
    console.error('Subscription check failed:', (error as Error).message);
    return false;
  }
}
