import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.57.0';

const PUBLIC_SITE_URL = (Deno.env.get('PUBLIC_SITE_URL') || '').replace(/\/$/, '');
const ALLOWED_ORIGINS = new Set((Deno.env.get('ALLOWED_ORIGINS') || PUBLIC_SITE_URL).split(',').map(value => value.trim().replace(/\/$/, '')).filter(Boolean));
const THROTTLE_PEPPER = Deno.env.get('THROTTLE_PEPPER') || '';
const headers = (origin: string | null) => ({
  'Access-Control-Allow-Origin': origin && ALLOWED_ORIGINS.has(origin) ? origin : PUBLIC_SITE_URL || 'null',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, idempotency-key',
  'Access-Control-Allow-Methods': 'POST, OPTIONS', 'Content-Type': 'application/json', 'Vary': 'Origin'
});
const respond = (body: Record<string, unknown>, status: number, origin: string | null) => new Response(JSON.stringify(body), { status, headers: headers(origin) });
const text = (value: unknown, maximum: number) => typeof value === 'string' ? value.trim().slice(0, maximum) : '';
const email = (value: unknown) => { const result = text(value, 254).toLowerCase(); return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(result) ? result : ''; };
const phone = (value: unknown) => { const result = text(value, 30); return /^[0-9+() -]{7,30}$/.test(result) ? result : ''; };
const key = (value: unknown) => { const result = text(value, 128); return /^[A-Za-z0-9_-]{16,128}$/.test(result) ? result : ''; };
const digest = async (value: string) => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)))).map(byte => byte.toString(16).padStart(2, '0')).join('');
const safeError = (error: unknown) => {
  if (error instanceof Error) return error.message;
  if (typeof error === 'object' && error !== null && 'message' in error && typeof error.message === 'string') return error.message;
  return '';
};
const statusFor = (message: string) => message.startsWith('rate_limit:') ? 429 : message.startsWith('conflict:') || message.startsWith('stock:') ? 409 : message.startsWith('validation:') ? 400 : 500;
const messageFor = (message: string) => {
  if (message.startsWith('rate_limit:')) return 'Please wait a moment before trying again.';
  if (message.startsWith('conflict:')) return 'This submission conflicts with an earlier request.';
  if (message.startsWith('stock:')) return 'One or more items are no longer available in the requested quantity.';
  if (message.startsWith('validation:')) return message.slice('validation:'.length).trim() || 'Please check the submitted details.';
  return 'Unable to process this request right now.';
};

Deno.serve(async request => {
  const requestId = crypto.randomUUID();
  const origin = request.headers.get('origin')?.replace(/\/$/, '') || null;
  if (request.method === 'OPTIONS') return new Response(null, { status: origin && ALLOWED_ORIGINS.has(origin) ? 204 : 403, headers: headers(origin) });
  if (request.method !== 'POST') return respond({ error: 'Method not allowed.' }, 405, origin);
  if (!origin || !ALLOWED_ORIGINS.has(origin)) return respond({ error: 'This origin is not allowed.' }, 403, origin);
  if (!THROTTLE_PEPPER) { console.error('THROTTLE_PEPPER is not configured'); return respond({ error: 'Service is temporarily unavailable.' }, 503, origin); }

  try {
    const input = await request.json();
    if (!input || typeof input !== 'object' || Array.isArray(input)) return respond({ error: 'Invalid request.' }, 400, origin);
    if (text(input.website, 200)) return respond({ ok: true }, 200, origin);
    const action = text(input.action, 20);
    const supabase = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!, { auth: { autoRefreshToken: false, persistSession: false } });
    if (action === 'contact') {
      const name = text(input.name, 100), contactEmail = email(input.email), subject = text(input.subject, 160), message = text(input.message, 4000);
      if (name.length < 1 || !contactEmail || message.length < 1) return respond({ error: 'Enter your name, a valid email address, and a message.' }, 400, origin);
      const fingerprint = await digest(`contact|${contactEmail}|${THROTTLE_PEPPER}`);
      const { data: allowed, error: throttleError } = await supabase.rpc('take_submission_slot', { p_action: 'contact', p_fingerprint: fingerprint, p_window_seconds: 30 });
      if (throttleError) throw throttleError;
      if (!allowed) return respond({ error: 'Please wait a moment before trying again.' }, 429, origin);
      const { error } = await supabase.from('contact_messages').insert({ id: crypto.randomUUID(), name, email: contactEmail, subject: subject || null, message });
      if (error) throw error;
      return respond({ ok: true }, 201, origin);
    }
    if (action === 'checkout') {
      const customer = input.customer && typeof input.customer === 'object' && !Array.isArray(input.customer) ? input.customer as Record<string, unknown> : {};
      const customerName = text(customer.name, 100), customerPhone = phone(customer.phone), customerEmail = text(customer.email, 254);
      const address = text(customer.address, 500), requestKey = key(input.idempotencyKey || request.headers.get('idempotency-key'));
      if (!customerName || !customerPhone || (customerEmail && !email(customerEmail)) || address.length < 5 || !requestKey || !Array.isArray(input.cart)) return respond({ error: 'Please check your checkout details and try again.' }, 400, origin);
      const fingerprint = await digest(`checkout|${customerPhone}|${email(customerEmail) || customerPhone}|${THROTTLE_PEPPER}`);
      const { data: allowed, error: throttleError } = await supabase.rpc('take_submission_slot', { p_action: 'checkout', p_fingerprint: fingerprint, p_window_seconds: 8 });
      if (throttleError) throw throttleError;
      if (!allowed) return respond({ error: 'Please wait a moment before trying again.' }, 429, origin);
      const { data, error } = await supabase.rpc('create_store_order', {
        p_cart: input.cart, p_customer_name: customerName, p_phone: customerPhone, p_email: customerEmail, p_address: address,
        p_district: text(customer.district, 100), p_division: text(customer.division, 100), p_delivery_area: text(input.deliveryArea, 30), p_payment_method: text(input.payment, 30), p_coupon: text(input.coupon, 50), p_idempotency_key: requestKey
      });
      if (error) throw error;
      return respond({ order: data }, 201, origin);
    }
    return respond({ error: 'Unknown request.' }, 400, origin);
  } catch (error) {
    const message = safeError(error);
    const status = statusFor(message);
    console.error(JSON.stringify({ event: 'storefront_request_failed', requestId, status, message }));
    return respond({ error: messageFor(message), requestId }, status, origin);
  }
});
