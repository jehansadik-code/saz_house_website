import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { stripTypeScriptTypes } from 'node:module';
import test from 'node:test';
import { runInNewContext } from 'node:vm';

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

test('storefront rejects disabled payment methods before reserving stock', async () => {
  const source = stripTypeScriptTypes((await load('supabase/functions/storefront/index.ts')).replace(/^import .*;\r?\n/m, ''));
  const calls = [];
  let handleRequest;
  const createClient = () => ({
    from(table) {
      assert.equal(table, 'store_state');
      return {
        select(columns) {
          assert.equal(columns, 'value');
          return {
            eq(field, value) {
              assert.equal(field, 'key');
              assert.equal(value, 'settings');
              return { maybeSingle: async () => ({ data: { value: { payments: { cod: true, bkash: false, nagad: false, card: false } } }, error: null }) };
            }
          };
        }
      };
    },
    async rpc(name, args) {
      calls.push({ name, args });
      if (name === 'take_submission_slot') return { data: true, error: null };
      if (name === 'create_store_order') return { data: { ref: 'SAZ-TESTORDER1', total: 100 }, error: null };
      throw new Error(`Unexpected RPC: ${name}`);
    }
  });
  runInNewContext(source, {
    createClient,
    Deno: {
      env: { get: name => ({ PUBLIC_SITE_URL: 'https://shop.example', ALLOWED_ORIGINS: 'https://shop.example', THROTTLE_PEPPER: 'test-pepper', SUPABASE_URL: 'https://db.example', SUPABASE_SERVICE_ROLE_KEY: 'test-key' })[name] },
      serve: handler => { handleRequest = handler; }
    },
    Response, TextEncoder, Uint8Array, crypto, console: { error() {} },
  });
  const checkout = payment => new Request('https://db.example/functions/v1/storefront', {
    method: 'POST',
    headers: { Origin: 'https://shop.example', 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'checkout', cart: [{ id: 'shirt', color: 'Black', size: 'M', qty: 1 }], customer: { name: 'Customer', phone: '01700000000', address: 'Dhaka, Bangladesh' }, payment, deliveryArea: 'dhaka', idempotencyKey: '0123456789abcdef' })
  });
  const blocked = await handleRequest(checkout('bKash'));
  assert.equal(blocked.status, 400);
  assert.match((await blocked.json()).error, /not available/);
  assert.equal(calls.length, 0);
  const accepted = await handleRequest(checkout('Cash on Delivery'));
  assert.equal(accepted.status, 201);
  assert.deepEqual(calls.map(call => call.name), ['take_submission_slot', 'create_store_order']);
  assert.equal(calls[1].args.p_payment_method, 'Cash on Delivery');
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

test('idempotent checkout resolves pgcrypto digest from Supabase extensions schema', async () => {
  const [migration, repair] = await Promise.all([
    load('supabase/20261026-production-hardening.sql'),
    load('supabase/20261027-fix-checkout-digest.sql')
  ]);
  assert.match(migration, /extensions\.digest\(/);
  assert.match(repair, /extensions\.digest\(text,text\)/);
  assert.match(repair, /create or replace function public\.create_store_order/i);
  assert.match(repair, /checkout_request\.request_hash/);
  assert.match(repair, /request_hash_value/);
});

test('browser retries retain one checkout key and disable duplicate submit clicks', async () => {
  const source = await load('assets/js/security.js');
  assert.match(source, /let checkoutIdempotencyKey/);
  assert.match(source, /if \(submit\?\.disabled\) return/);
  assert.match(source, /idempotencyKey: nextCheckoutKey\(\)/);
  assert.match(source, /submit\.disabled = false/);
});

test('checkout form and database contract allow removed optional address fields', async () => {
  const [app, edge, sql] = await Promise.all([
    load('assets/js/app.js'),
    load('supabase/functions/storefront/index.ts'),
    load('supabase/20261026-production-hardening.sql')
  ]);
  assert.match(app, /name='phone' type='tel' required minlength='7' maxlength='30'/);
  assert.doesNotMatch(app, /name='email'/);
  assert.doesNotMatch(app, /name='district'/);
  assert.doesNotMatch(app, /name='division'/);
  assert.match(edge, /p_email: customerEmail/);
  assert.match(edge, /p_district: text\(customer\.district, 100\)/);
  assert.match(sql, /nullif\(lower\(trim\(p_email\)\),''\)/);
  assert.match(sql, /nullif\(trim\(p_district\),''\)/);
  assert.match(sql, /nullif\(trim\(p_division\),''\)/);
});

test('a missing hardened checkout handler cannot fall back to browser-only orders', async () => {
  const app = await load('assets/js/app.js');
  assert.match(app, /Secure checkout is temporarily unavailable/);
  assert.doesNotMatch(app, /if\(e\.target\.id==='checkout-form'\)\{for\(const row of cart\)/);
});

test('admin order status changes use the database inventory transaction only', async () => {
  const [app, client, migration] = await Promise.all([
    load('assets/js/app.js'),
    load('assets/js/supabase-client.js'),
    load('supabase/20261026-production-hardening.sql')
  ]);
  assert.match(app, /The server owns inventory/);
  assert.match(app, /client\.rpc\('update_staff_order_status'/);
  assert.match(app, /hydrate\(\{force:true\}\)/);
  assert.doesNotMatch(app, /adjustOrderInventory/);
  assert.match(client, /async function hydrate\(\{ force = false \} = \{\}\)/);
  assert.match(migration, /select status,line_items into current_status,order_lines.*for update/is);
  assert.match(migration, /if current_status='Cancelled' or p_status='Cancelled'/);
});

test('every entry page loads the cache-busted client before checkout hardening', async () => {
  const pages = (await readdir(root)).filter(name => name.endsWith('.html'));
  assert.ok(pages.includes('checkout.html'));
  for (const page of pages) {
    const source = await load(page);
    assert.match(source, /styles\.css\?v=20261027-3/);
    assert.match(source, /supabase-client\.js\?v=20261027-3/);
    assert.match(source, /security\.js\?v=20261027-3/);
    assert.ok(source.indexOf('supabase-client.js?v=20261027-3') < source.indexOf('assets\/js\/security.js'));
    assert.ok(source.indexOf('assets\/js\/security.js') < source.indexOf('assets\/js\/app.js?v=20261027-3'));
  }
});

test('checkout errors provide a safe correlation id and the root logo asset exists', async () => {
  const [edge, security] = await Promise.all([
    load('supabase/functions/storefront/index.ts'),
    load('assets/js/security.js')
  ]);
  assert.match(edge, /storefront_request_failed/);
  assert.match(edge, /requestId/);
  assert.match(security, /Reference: \$\{result\.requestId\}/);
  const logo = await readFile(new URL('logo.png', root));
  assert.ok(logo.length > 0);
});
