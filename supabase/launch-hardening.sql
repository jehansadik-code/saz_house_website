-- Production hardening migration. Run after schema.sql in the Supabase SQL editor.
-- Safe to run again: existing named constraints are preserved.
-- Checkout and contact writes now go through the Edge Function, never directly from a browser.

do $$
begin
  if not exists (select 1 from pg_constraint where conrelid = 'public.orders'::regclass and conname = 'orders_reference_format') then
    alter table public.orders add constraint orders_reference_format check (reference ~ '^SAZ-[A-Z0-9]{10}$') not valid;
  end if;
  if not exists (select 1 from pg_constraint where conrelid = 'public.orders'::regclass and conname = 'orders_customer_name_length') then
    alter table public.orders add constraint orders_customer_name_length check (char_length(customer_name) between 1 and 100) not valid;
  end if;
  if not exists (select 1 from pg_constraint where conrelid = 'public.orders'::regclass and conname = 'orders_phone_length') then
    alter table public.orders add constraint orders_phone_length check (char_length(phone) between 7 and 30) not valid;
  end if;
  if not exists (select 1 from pg_constraint where conrelid = 'public.orders'::regclass and conname = 'orders_total_nonnegative') then
    alter table public.orders add constraint orders_total_nonnegative check (total >= 0) not valid;
  end if;
  if not exists (select 1 from pg_constraint where conrelid = 'public.contact_messages'::regclass and conname = 'contact_name_length') then
    alter table public.contact_messages add constraint contact_name_length check (char_length(name) between 1 and 100) not valid;
  end if;
  if not exists (select 1 from pg_constraint where conrelid = 'public.contact_messages'::regclass and conname = 'contact_message_length') then
    alter table public.contact_messages add constraint contact_message_length check (char_length(message) between 1 and 4000) not valid;
  end if;
end $$;

create table if not exists public.submission_throttle (
  fingerprint text primary key,
  action text not null check (action in ('checkout', 'contact')),
  last_seen timestamptz not null default now()
);
alter table public.submission_throttle enable row level security;

drop policy if exists "customers can place orders" on public.orders;
drop policy if exists "visitors can send contact messages" on public.contact_messages;
revoke all on table public.orders, public.contact_messages, public.submission_throttle from anon, authenticated;

create or replace function public.create_store_order(
  p_cart jsonb,
  p_customer_name text,
  p_phone text,
  p_email text,
  p_address text,
  p_district text,
  p_division text,
  p_delivery_area text,
  p_payment_method text,
  p_coupon text
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  products jsonb;
  settings jsonb;
  coupons jsonb;
  cart_item jsonb;
  product jsonb;
  coupon jsonb;
  item_index bigint;
  quantity integer;
  stock integer;
  unit_price numeric(12,2);
  subtotal numeric(12,2) := 0;
  shipping numeric(12,2) := 0;
  discount numeric(12,2) := 0;
  order_total numeric(12,2) := 0;
  line_items jsonb := '[]'::jsonb;
  reference_code text := 'SAZ-' || upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 10));
  status_value text := 'Processing';
begin
  if jsonb_typeof(p_cart) <> 'array' or jsonb_array_length(p_cart) = 0 or jsonb_array_length(p_cart) > 25 then
    raise exception 'Your cart is invalid.';
  end if;
  if char_length(trim(coalesce(p_customer_name, ''))) not between 1 and 100
     or char_length(trim(coalesce(p_phone, ''))) not between 7 and 30
     or char_length(trim(coalesce(p_address, ''))) not between 5 and 500 then
    raise exception 'Please provide valid delivery details.';
  end if;
  if p_payment_method not in ('Cash on Delivery', 'bKash', 'Nagad', 'Card (demo)') then
    raise exception 'Invalid payment method.';
  end if;

  select value into products from public.store_state where key = 'products' for update;
  select value into settings from public.store_state where key = 'settings';
  select value into coupons from public.store_state where key = 'coupons';
  if products is null or settings is null then raise exception 'Store is not ready.'; end if;

  for cart_item in select value from jsonb_array_elements(p_cart)
  loop
    quantity := coalesce(nullif(cart_item->>'qty', '')::integer, 0);
    if quantity < 1 or quantity > 20 or coalesce(cart_item->>'id', '') !~ '^[a-zA-Z0-9_-]{1,100}$' then
      raise exception 'Invalid cart item.';
    end if;
    select value, ordinality - 1 into product, item_index
      from jsonb_array_elements(products) with ordinality
      where value->>'id' = cart_item->>'id' and coalesce((value->>'active')::boolean, true)
      limit 1;
    if product is null then raise exception 'A product is no longer available.'; end if;
    stock := coalesce(nullif(product->>'stock', '')::integer, 0);
    unit_price := coalesce(nullif(product->>'price', '')::numeric, -1);
    if stock < quantity or unit_price < 0 then raise exception 'Insufficient stock.'; end if;
    products := jsonb_set(products, array[item_index::text, 'stock'], to_jsonb(stock - quantity), false);
    subtotal := subtotal + unit_price * quantity;
    line_items := line_items || jsonb_build_array(jsonb_build_object(
      'id', product->>'id', 'name', left(coalesce(product->>'name', ''), 160),
      'color', left(coalesce(cart_item->>'color', product->>'color', ''), 60),
      'size', left(coalesce(cart_item->>'size', ''), 30), 'qty', quantity, 'price', unit_price
    ));
  end loop;

  if p_delivery_area = 'dhaka' then shipping := coalesce(nullif(settings->>'dhaka', '')::numeric, 0);
  elsif p_delivery_area = 'outside' then shipping := coalesce(nullif(settings->>'outside', '')::numeric, 0);
  else raise exception 'Select a delivery area.'; end if;
  if coalesce(nullif(settings->>'freeThreshold', '')::numeric, 0) > 0
     and subtotal >= (settings->>'freeThreshold')::numeric then shipping := 0; end if;

  if p_coupon is not null and trim(p_coupon) <> '' then
    select value into coupon from jsonb_array_elements(coalesce(coupons, '[]'::jsonb))
      where upper(value->>'code') = upper(trim(p_coupon)) and coalesce((value->>'active')::boolean, false)
      and subtotal >= coalesce(nullif(value->>'minimum', '')::numeric, 0) limit 1;
    if coupon is null then raise exception 'Coupon is invalid.'; end if;
    discount := case when coupon->>'type' = 'percent'
      then least(subtotal, round(subtotal * coalesce(nullif(coupon->>'value', '')::numeric, 0) / 100))
      else least(subtotal, coalesce(nullif(coupon->>'value', '')::numeric, 0)) end;
  end if;
  order_total := greatest(0, subtotal + shipping - discount);

  update public.store_state set value = products, updated_at = now() where key = 'products';
  insert into public.orders(reference, customer_name, phone, email, address, city, district, division,
    payment_method, subtotal, shipping, discount, total, coupon, status, line_items)
  values (reference_code, trim(p_customer_name), trim(p_phone), nullif(trim(p_email), ''), trim(p_address),
    case when p_delivery_area = 'dhaka' then 'Dhaka' else 'Outside Dhaka' end, nullif(trim(p_district), ''),
    nullif(trim(p_division), ''), p_payment_method, subtotal, shipping, discount, order_total,
    nullif(upper(trim(p_coupon)), ''), status_value, line_items);
  return jsonb_build_object('ref', reference_code, 'total', order_total, 'status', status_value);
end;
$$;

revoke all on function public.create_store_order(jsonb, text, text, text, text, text, text, text, text, text) from public, anon, authenticated;
grant execute on function public.create_store_order(jsonb, text, text, text, text, text, text, text, text, text) to service_role;
