import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const root = new URL('..', import.meta.url);
const load = path => readFile(new URL(path, root), 'utf8');

test('storefront requires an origin, a pepper, and an idempotency key', async () => {
  const source = await load('supabase/functions/storefront/index.ts');
  assert.match(source, /!origin \|\| !ALLOWED_ORIGINS\.has\(origin\)/);
  assert.match(source, /THROTTLE_PEPPER is not configured/);
  assert.match(source, /idempotencyKey/);
  assert.match(source, /p_idempotency_key: requestKey/);
  assert.doesNotMatch(source, /x-forwarded-for/);
});

test('migration keeps the legacy RPC and adds atomic idempotency and throttling', async () => {
  const sql = await load('supabase/20261026-production-hardening.sql');
  assert.match(sql, /create table if not exists public\.checkout_requests/i);
  assert.match(sql, /on conflict \(fingerprint\) do update/i);
  assert.match(sql, /where public\.submission_throttle\.last_seen <= now\(\)/i);
  assert.match(sql, /for update/i);
  assert.match(sql, /p_idempotency_key text/i);
  assert.match(sql, /Preserve all existing 10-argument callers/i);
  assert.match(sql, /grant execute.*to service_role/is);
});

test('browser retries retain one checkout key and disable duplicate submit clicks', async () => {
  const source = await load('assets/js/security.js');
  assert.match(source, /let checkoutIdempotencyKey/);
  assert.match(source, /if \(submit\?\.disabled\) return/);
  assert.match(source, /idempotencyKey: nextCheckoutKey\(\)/);
  assert.match(source, /submit\.disabled = false/);
});
