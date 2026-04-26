#!/usr/bin/env tsx
/**
 * One-time migration: grants a subscription to all existing users
 * who do not already have one in the subscriptions collection.
 *
 * Usage:
 *   pnpm tsx scripts/migrate-existing-users.ts --plan trial_3m
 *   pnpm tsx scripts/migrate-existing-users.ts --plan annual
 *   pnpm tsx scripts/migrate-existing-users.ts --plan lifetime
 *   pnpm tsx scripts/migrate-existing-users.ts --plan biannual
 *   pnpm tsx scripts/migrate-existing-users.ts --dry-run --plan lifetime
 *
 * Options:
 *   --plan      Plan to grant: trial_1d | trial_2w | trial_3m | monthly | annual | biannual | lifetime
 *   --dry-run   Print what would happen without writing anything
 */

import 'dotenv/config';
import { db, admin } from '../src/config/firebase';
import { LICENSE_PLAN_DURATIONS_DAYS } from '../src/helpers/license';

const args = process.argv.slice(2);
const get = (flag: string): string | null => { const i = args.indexOf(flag); return i !== -1 ? args[i + 1] : null; };
const has = (flag: string): boolean => args.includes(flag);

const plan = get('--plan');
const dryRun = has('--dry-run');
const planChoices = Object.keys(LICENSE_PLAN_DURATIONS_DAYS);

if (!plan || !(plan in LICENSE_PLAN_DURATIONS_DAYS)) {
  console.error(`Error: --plan must be one of: ${planChoices.join(', ')}`);
  process.exit(1);
}

async function main(): Promise<void> {
  const duration_days =
    LICENSE_PLAN_DURATIONS_DAYS[
      plan as keyof typeof LICENSE_PLAN_DURATIONS_DAYS
    ];

  console.log(`\nMigration config:`);
  console.log(`  Plan:    ${plan}`);
  console.log(`  Expiry:  ${duration_days ? `${duration_days} days from now` : 'never (lifetime)'}`);
  console.log(`  Mode:    ${dryRun ? 'DRY RUN (no writes)' : 'LIVE'}\n`);

  const usersSnap = await db.collection('users').get();
  console.log(`Found ${usersSnap.size} user(s) in users collection.\n`);

  let granted = 0;
  let skipped = 0;
  let errors = 0;

  for (const userDoc of usersSnap.docs) {
    const email = userDoc.id;

    try {
      const subDoc = await db.collection('subscriptions').doc(email).get();

      if (subDoc.exists) {
        const sub = subDoc.data()!;
        console.log(`  SKIP   ${email}  (subscription already exists: ${sub['plan']} / ${sub['status']})`);
        skipped++;
        continue;
      }

      const expires_at = duration_days
        ? admin.firestore.Timestamp.fromDate(new Date(Date.now() + duration_days * 24 * 60 * 60 * 1000))
        : null;

      if (dryRun) {
        console.log(`  WOULD GRANT  ${email}  → ${plan}${expires_at ? ` until ${expires_at.toDate().toISOString().split('T')[0]}` : ' (lifetime)'}`);
      } else {
        await db.collection('subscriptions').doc(email).set({
          status: 'active',
          plan,
          expires_at,
          activated_at: admin.firestore.FieldValue.serverTimestamp(),
          renewed_at: null,
          key_hash: 'migration',
        });

        await db.collection('license_activations').doc().set({
          email,
          key_hash: 'migration',
          action: 'activated',
          plan,
          expires_at,
          timestamp: admin.firestore.FieldValue.serverTimestamp(),
          ip: 'migration-script',
        });

        console.log(`  GRANTED  ${email}  → ${plan}${expires_at ? ` until ${expires_at.toDate().toISOString().split('T')[0]}` : ' (lifetime)'}`);
      }

      granted++;
    } catch (err) {
      console.error(`  ERROR    ${email}  → ${(err as Error).message}`);
      errors++;
    }
  }

  console.log(`\n─────────────────────────────────`);
  console.log(`Granted:  ${granted}`);
  console.log(`Skipped:  ${skipped} (already had subscription)`);
  console.log(`Errors:   ${errors}`);
  if (dryRun) console.log(`\nThis was a dry run. Re-run without --dry-run to apply.`);

  await admin.app().delete();
}

main().catch((err: Error) => {
  console.error('Migration failed:', err.message);
  process.exit(1);
});
