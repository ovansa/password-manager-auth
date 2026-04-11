import crypto from 'crypto';
import { db } from '../config/firebase';

export interface LicensePayload {
  status: string;
  plan: string | null;
  expires_at: string | null;
}

export const hashKey = (key: string): string =>
  crypto.createHash('sha256').update(key.trim().toUpperCase()).digest('hex');

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
    plan: sub['plan'] ?? null,
    expires_at: sub['expires_at'] ? sub['expires_at'].toDate().toISOString() : null,
  };
}

/**
 * Check if user has a valid (active) subscription.
 */
export async function checkSubscriptionStatus(email: string): Promise<boolean> {
  try {
    if (process.env.NODE_ENV === 'development') return true;

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
