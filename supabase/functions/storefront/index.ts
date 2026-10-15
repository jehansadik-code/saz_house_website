import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.57.0';

const corsHeaders = {
  'Access-Control-Allow-Origin': Deno.env.get('PUBLIC_SITE_URL') || 'null',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Vary': 'Origin',
  'Content-Type': 'application/json'
};
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: corsHeaders });
const text = (value: unknown, max: number) => typeof value === 'string' ? value.trim().slice(0, max) : '';

Deno.serve(async request => {
  if (request.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  if (request.method !== 'POST') return json({ error: 'Method not allowed.' }, 405);
  const expectedOrigin = Deno.env.get('PUBLIC_SITE_URL');
  const origin = request.headers.get('origin');
  if (expectedOrigin && origin !== expectedOrigin) return json({ error: 'Invalid origin.' }, 403);

  try {
    const input = await request.json();
    if (text(input.website, 200)) return json({ ok: true }); // Honeypot: pretend success.
    const supabase = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
    );
    const action = text(input.action, 20);
    const fingerprint = `${action}:${request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown'}`;
    const { data: previous } = await supabase.from('submission_throttle')
      .select('last_seen').eq('fingerprint', fingerprint).maybeSingle();
    if (previous && Date.now() - new Date(previous.last_seen).getTime() < 15_000) {
      return json({ error: 'Please wait a moment before trying again.' }, 429);
    }
    await supabase.from('submission_throttle').upsert({ fingerprint, action, last_seen: new Date().toISOString() });
    if (input.action === 'contact') {
      const name = text(input.name, 100), email = text(input.email, 254);
      const subject = text(input.subject, 160), message = text(input.message, 4000);
      if (!name || !email.includes('@') || !message) return json({ error: 'Please complete the required fields.' }, 400);
      const { error } = await supabase.from('contact_messages').insert({
        id: crypto.randomUUID(), name, email, subject: subject || null, message
      });
      if (error) throw error;
      return json({ ok: true });
    }
    if (input.action === 'checkout') {
      const customer = input.customer || {};
      const { data, error } = await supabase.rpc('create_store_order', {
        p_cart: Array.isArray(input.cart) ? input.cart : [],
        p_customer_name: text(customer.name, 100), p_phone: text(customer.phone, 30),
        p_email: text(customer.email, 254), p_address: text(customer.address, 500),
        p_district: text(customer.district, 100), p_division: text(customer.division, 100),
        p_delivery_area: text(input.deliveryArea, 30), p_payment_method: text(input.payment, 30),
        p_coupon: text(input.coupon, 50)
      });
      if (error) throw error;
      return json({ order: data });
    }
    return json({ error: 'Unknown request.' }, 400);
  } catch (error) {
    console.error(error);
    return json({ error: 'Unable to process this request.' }, 400);
  }
});
