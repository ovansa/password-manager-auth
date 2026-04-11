#!/usr/bin/env tsx
/**
 * Passa license key generator.
 *
 * Usage:
 *   pnpm tsx scripts/generate-key.ts --plan monthly
 *   pnpm tsx scripts/generate-key.ts --plan biannual
 *   pnpm tsx scripts/generate-key.ts --plan lifetime
 *   pnpm tsx scripts/generate-key.ts --plan trial_2w
 *   pnpm tsx scripts/generate-key.ts --plan monthly --count 5
 *   pnpm tsx scripts/generate-key.ts --plan monthly --note "sent to John"
 *
 * Plans:
 *   trial_2w  → 14 days
 *   monthly   → 30 days
 *   biannual  → 180 days
 *   lifetime  → no expiry
 */

import 'dotenv/config';
import crypto from 'crypto';
import { db, admin } from '../src/config/firebase';
import { hashKey } from '../src/helpers/license';

// ── Plans ─────────────────────────────────────────────────────────────────────

const PLANS: Record<string, { duration_days: number | null }> = {
  trial_2w: { duration_days: 14 },
  monthly: { duration_days: 30 },
  biannual: { duration_days: 180 },
  lifetime: { duration_days: null },
};

// ── Args ──────────────────────────────────────────────────────────────────────

const args = process.argv.slice(2);
const get = (flag: string): string | null => {
  const i = args.indexOf(flag);
  return i !== -1 ? args[i + 1] : null;
};

const plan = get('--plan');
const count = parseInt(get('--count') ?? '1', 10);
const note = get('--note') ?? '';

if (!plan || !PLANS[plan]) {
  console.error(
    `Error: --plan must be one of: ${Object.keys(PLANS).join(', ')}`,
  );
  process.exit(1);
}

// ── Key generation ────────────────────────────────────────────────────────────

function generateKey(): string {
  const segment = () => crypto.randomBytes(2).toString('hex').toUpperCase();
  return `PASSA-${segment()}-${segment()}-${segment()}-${segment()}`;
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const { duration_days } = PLANS[plan!];

  for (let i = 0; i < count; i++) {
    const key = generateKey();
    // hashKey normalises (trim + toUpperCase) - matches exactly what the server does
    const keyHash = hashKey(key);

    await db.collection('license_keys').doc(keyHash).set({
      plan,
      duration_days,
      max_uses: 1,
      use_count: 0,
      revoked: false,
      activated_by: null,
      created_at: admin.firestore.FieldValue.serverTimestamp(),
      notes: note,
    });

    console.log(`✓ ${key}  [${plan}]`);
  }

  console.log(
    `\nGenerated ${count} key(s). Store these securely - they cannot be recovered from the database.`,
  );
  await admin.app().delete();
}

main().catch((err: Error) => {
  console.error('Failed:', err.message);
  process.exit(1);
});
