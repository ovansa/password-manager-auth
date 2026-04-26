#!/usr/bin/env tsx
/**
 * Passa license key generator.
 *
 * Usage:
 *   pnpm tsx scripts/generate-key.ts --plan trial_1d
 *   pnpm tsx scripts/generate-key.ts --plan monthly
 *   pnpm tsx scripts/generate-key.ts --plan annual
 *   pnpm tsx scripts/generate-key.ts --plan biannual
 *   pnpm tsx scripts/generate-key.ts --plan lifetime
 *   pnpm tsx scripts/generate-key.ts --plan trial_2w
 *   pnpm tsx scripts/generate-key.ts --plan trial_3m
 *   pnpm tsx scripts/generate-key.ts --plan monthly --count 5
 *   pnpm tsx scripts/generate-key.ts --plan monthly --note "sent to John"
 *   pnpm tsx scripts/generate-key.ts --plan trial_3m --count 20 --note "early access batch 1"
 *
 * Plans:
 *   trial_1d  → 1 day (testing)
 *   trial_2w  → 14 days
 *   trial_3m  → 90 days (early access offer)
 *   monthly   → 30 days
 *   annual    → 365 days
 *   biannual  → 180 days
 *   lifetime  → no expiry
 */

import 'dotenv/config';
import crypto from 'crypto';
import { db, admin } from '../src/config/firebase';
import { hashKey, LICENSE_PLAN_DURATIONS_DAYS } from '../src/helpers/license';

// ── Args ──────────────────────────────────────────────────────────────────────

const args = process.argv.slice(2);
const get = (flag: string): string | null => {
  const i = args.indexOf(flag);
  return i !== -1 ? args[i + 1] : null;
};

const plan = get('--plan');
const count = parseInt(get('--count') ?? '1', 10);
const note = get('--note') ?? '';
const planChoices = Object.keys(LICENSE_PLAN_DURATIONS_DAYS);

if (!plan || !(plan in LICENSE_PLAN_DURATIONS_DAYS)) {
  console.error(
    `Error: --plan must be one of: ${planChoices.join(', ')}`,
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
  const duration_days =
    LICENSE_PLAN_DURATIONS_DAYS[
      plan as keyof typeof LICENSE_PLAN_DURATIONS_DAYS
    ];

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
