-- Additive migration: run once after the existing SAZ migrations. It does not delete or rewrite business data.
begin;

create table if not exists public.checkout_requests (
  idempotency_key text primary key check (idempotency_key ~ '^[A-Za-z0-9_-]{16,128}$'),
  request_hash text not null check (request_hash ~ '^[a-f0-9]{64}$'),
  response jsonb,
  order_reference text unique references public.orders(reference) on delete restrict,
  created_at timestamptz not null default now()
);
alter table public.checkout_requests enable row level security;
revoke all on table public.checkout_requests from public, anon, authenticated;

-- Atomic, database-side throttle. The Edge Function supplies a server-peppered digest,
-- so this is not keyed to an untrusted forwarding/IP header.
create or replace function public.take_submission_slot(p_action text, p_fingerprint text, p_window_seconds integer default 15)
returns boolean language plpgsql security definer set search_path = public as $$
declare accepted boolean;
begin
  if p_action not in ('checkout', 'contact') or p_fingerprint !~ '^[a-f0-9]{64}$' or p_window_seconds not between 1 and 3600 then
    raise exception 'validation: Invalid submission request.';
  end if;
  insert into public.submission_throttle(fingerprint, action, last_seen) values (p_fingerprint, p_action, now())
  on conflict (fingerprint) do update set last_seen=excluded.last_seen, action=excluded.action
    where public.submission_throttle.last_seen <= now() - make_interval(secs => p_window_seconds)
  returning true into accepted;
  return coalesce(accepted, false);
end; $$;
revoke all on function public.take_submission_slot(text,text,integer) from public, anon, authenticated;
grant execute on function public.take_submission_slot(text,text,integer) to service_role;

-- New 11-argument RPC. It locks the request row and products row in one transaction,
-- so concurrent/retried identical requests return the original order without reserving stock twice.
create or replace function public.create_store_order(
  p_cart jsonb,p_customer_name text,p_phone text,p_email text,p_address text,p_district text,p_division text,
  p_delivery_area text,p_payment_method text,p_coupon text,p_idempotency_key text
) returns jsonb language plpgsql security definer set search_path = public as $$
declare
  products jsonb; settings jsonb; coupons jsonb; cart_item jsonb; product jsonb; original_product jsonb; coupon jsonb; variants jsonb;
  item_index bigint; variant_index bigint; quantity integer; stock integer; unit_price numeric(12,2); selected_color text; selected_size text;
  subtotal numeric(12,2):=0; shipping numeric(12,2):=0; discount numeric(12,2):=0; total_value numeric(12,2):=0; lines jsonb:='[]'::jsonb;
  reference_code text:='SAZ-'||upper(substr(replace(gen_random_uuid()::text,'-',''),1,10)); request_hash text; existing_hash text; result jsonb;
begin
  if p_idempotency_key !~ '^[A-Za-z0-9_-]{16,128}$' then raise exception 'validation: Invalid checkout request.'; end if;
  if jsonb_typeof(p_cart)<>'array' or jsonb_array_length(p_cart)=0 or jsonb_array_length(p_cart)>25 then raise exception 'validation: Your cart is invalid.'; end if;
  if char_length(trim(coalesce(p_customer_name,''))) not between 1 and 100 or trim(coalesce(p_phone,'')) !~ '^[0-9+() -]{7,30}$' or char_length(trim(coalesce(p_address,''))) not between 5 and 500 then raise exception 'validation: Please provide valid delivery details.'; end if;
  if nullif(trim(coalesce(p_email,'')),'') is not null and lower(trim(p_email)) !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$' then raise exception 'validation: Enter a valid email address.'; end if;
  if p_payment_method not in ('Cash on Delivery','bKash','Nagad','Card (demo)') then raise exception 'validation: Invalid payment method.'; end if;
  request_hash:=encode(digest(jsonb_build_object('cart',p_cart,'name',trim(p_customer_name),'phone',trim(p_phone),'email',lower(trim(coalesce(p_email,''))),'address',trim(p_address),'district',trim(coalesce(p_district,'')),'division',trim(coalesce(p_division,'')),'delivery',p_delivery_area,'payment',p_payment_method,'coupon',upper(trim(coalesce(p_coupon,''))))::text,'sha256'),'hex');
  insert into public.checkout_requests(idempotency_key,request_hash) values(p_idempotency_key,request_hash) on conflict do nothing;
  select request_hash,response into existing_hash,result from public.checkout_requests where idempotency_key=p_idempotency_key for update;
  if existing_hash<>request_hash then raise exception 'conflict: Checkout request key was reused with different details.'; end if;
  if result is not null then return result; end if;
  select value into products from public.store_state where key='products' for update;
  select value into settings from public.store_state where key='settings'; select value into coupons from public.store_state where key='coupons';
  if products is null or settings is null then raise exception 'validation: Store is not ready.'; end if;
  for cart_item in select value from jsonb_array_elements(p_cart) loop
    quantity:=coalesce(nullif(cart_item->>'qty','')::integer,0); selected_color:=left(trim(coalesce(cart_item->>'color','')),60); selected_size:=left(trim(coalesce(cart_item->>'size','')),30);
    if quantity<1 or quantity>20 or coalesce(cart_item->>'id','') !~ '^[a-zA-Z0-9_-]{1,100}$' or selected_color='' or selected_size='' then raise exception 'validation: Invalid cart item.'; end if;
    select value,ordinality-1 into product,item_index from jsonb_array_elements(products) with ordinality where value->>'id'=cart_item->>'id' and coalesce((value->>'active')::boolean,true) limit 1;
    if product is null then raise exception 'stock: A product is no longer available.'; end if; original_product:=product; unit_price:=coalesce(nullif(product->>'price','')::numeric,-1); if unit_price<0 then raise exception 'validation: Invalid product price.'; end if;
    if jsonb_typeof(product->'variants')='array' and jsonb_array_length(product->'variants')>0 then
      variants:=product->'variants'; select value,ordinality-1 into product,variant_index from jsonb_array_elements(variants) with ordinality where value->>'color'=selected_color and value->>'size'=selected_size limit 1;
      if product is null then raise exception 'stock: This colour and size is unavailable.'; end if; stock:=coalesce(nullif(product->>'stock','')::integer,0); if stock<quantity then raise exception 'stock: Insufficient stock.'; end if;
      variants:=jsonb_set(variants,array[variant_index::text,'stock'],to_jsonb(stock-quantity),false); products:=jsonb_set(products,array[item_index::text,'variants'],variants,false); products:=jsonb_set(products,array[item_index::text,'stock'],to_jsonb((select coalesce(sum(coalesce(nullif(value->>'stock','')::integer,0)),0) from jsonb_array_elements(variants))),false);
    else
      if not exists(select 1 from jsonb_array_elements_text(case when jsonb_typeof(original_product->'colors')='array' and jsonb_array_length(original_product->'colors')>0 then original_product->'colors' else jsonb_build_array(coalesce(original_product->>'color','Black')) end) c(value) where c.value=selected_color) or not exists(select 1 from jsonb_array_elements_text(case when jsonb_typeof(original_product->'sizes')='array' and jsonb_array_length(original_product->'sizes')>0 then original_product->'sizes' else '["One Size"]'::jsonb end) s(value) where s.value=selected_size) then raise exception 'stock: This colour and size is unavailable.'; end if;
      stock:=coalesce(nullif(product->>'stock','')::integer,0); if stock<quantity then raise exception 'stock: Insufficient stock.'; end if; products:=jsonb_set(products,array[item_index::text,'stock'],to_jsonb(stock-quantity),false);
    end if;
    subtotal:=subtotal+unit_price*quantity; lines:=lines||jsonb_build_array(jsonb_build_object('id',cart_item->>'id','name',left(coalesce(original_product->>'name',''),160),'color',selected_color,'size',selected_size,'qty',quantity,'price',unit_price));
  end loop;
  if p_delivery_area='dhaka' then shipping:=coalesce(nullif(settings->>'dhaka','')::numeric,0); elsif p_delivery_area='outside' then shipping:=coalesce(nullif(settings->>'outside','')::numeric,0); else raise exception 'validation: Select a delivery area.'; end if;
  if coalesce(nullif(settings->>'freeThreshold','')::numeric,0)>0 and subtotal>=(settings->>'freeThreshold')::numeric then shipping:=0; end if;
  if nullif(trim(coalesce(p_coupon,'')),'') is not null then select value into coupon from jsonb_array_elements(coalesce(coupons,'[]'::jsonb)) where upper(value->>'code')=upper(trim(p_coupon)) and coalesce((value->>'active')::boolean,false) and subtotal>=coalesce(nullif(value->>'minimum','')::numeric,0) limit 1; if coupon is null then raise exception 'validation: Coupon is invalid.'; end if; discount:=case when coupon->>'type'='percent' then least(subtotal,round(subtotal*coalesce(nullif(coupon->>'value','')::numeric,0)/100)) else least(subtotal,coalesce(nullif(coupon->>'value','')::numeric,0)) end; end if;
  total_value:=greatest(0,subtotal+shipping-discount); update public.store_state set value=products,updated_at=now() where key='products';
  insert into public.orders(reference,customer_name,phone,email,address,city,district,division,payment_method,subtotal,shipping,discount,total,coupon,status,line_items) values(reference_code,trim(p_customer_name),trim(p_phone),nullif(lower(trim(p_email)),''),trim(p_address),case when p_delivery_area='dhaka' then 'Dhaka' else 'Outside Dhaka' end,nullif(trim(p_district),''),nullif(trim(p_division),''),p_payment_method,subtotal,shipping,discount,total_value,nullif(upper(trim(p_coupon)),''),'Processing',lines);
  result:=jsonb_build_object('ref',reference_code,'total',total_value,'status','Processing'); update public.checkout_requests set response=result,order_reference=reference_code where idempotency_key=p_idempotency_key; return result;
end; $$;

-- Cancellation returns precisely the recorded line quantities. Reactivation takes
-- them back only when stock is still available; both order and products rows are locked.
create or replace function public.update_staff_order_status(p_reference text,p_status text)
returns void language plpgsql security definer set search_path = public as $$
declare current_status text; order_lines jsonb; products jsonb; line jsonb; product jsonb; variants jsonb; item_index bigint; variant_index bigint; quantity integer; stock integer; direction integer;
begin
  if not public.has_permission('orders.manage') then raise exception 'validation: You do not have permission to update orders.'; end if;
  if p_status not in ('Processing','Shipped','Delivered','Cancelled') then raise exception 'validation: Choose a valid order status.'; end if;
  select status,line_items into current_status,order_lines from public.orders where reference=p_reference for update;
  if not found then raise exception 'validation: That order no longer exists.'; end if;
  if current_status=p_status then return; end if;
  if current_status='Cancelled' or p_status='Cancelled' then
    direction:=case when p_status='Cancelled' then 1 else -1 end;
    select value into products from public.store_state where key='products' for update;
    if products is null then raise exception 'validation: Store inventory is unavailable.'; end if;
    for line in select value from jsonb_array_elements(coalesce(order_lines,'[]'::jsonb)) loop
      quantity:=coalesce(nullif(line->>'qty','')::integer,0); if quantity<1 then raise exception 'validation: Order inventory data is invalid.'; end if;
      select value,ordinality-1 into product,item_index from jsonb_array_elements(products) with ordinality where value->>'id'=line->>'id' limit 1;
      if product is null then raise exception 'stock: The ordered product no longer exists.'; end if;
      if jsonb_typeof(product->'variants')='array' and jsonb_array_length(product->'variants')>0 then
        variants:=product->'variants'; select value,ordinality-1 into product,variant_index from jsonb_array_elements(variants) with ordinality where value->>'color'=line->>'color' and value->>'size'=line->>'size' limit 1;
        if product is null then raise exception 'stock: The ordered variant no longer exists.'; end if; stock:=coalesce(nullif(product->>'stock','')::integer,0); if direction=-1 and stock<quantity then raise exception 'stock: Insufficient stock to reactivate this order.'; end if;
        variants:=jsonb_set(variants,array[variant_index::text,'stock'],to_jsonb(stock+direction*quantity),false); products:=jsonb_set(products,array[item_index::text,'variants'],variants,false); products:=jsonb_set(products,array[item_index::text,'stock'],to_jsonb((select coalesce(sum(coalesce(nullif(value->>'stock','')::integer,0)),0) from jsonb_array_elements(variants))),false);
      else
        stock:=coalesce(nullif(product->>'stock','')::integer,0); if direction=-1 and stock<quantity then raise exception 'stock: Insufficient stock to reactivate this order.'; end if; products:=jsonb_set(products,array[item_index::text,'stock'],to_jsonb(stock+direction*quantity),false);
      end if;
    end loop;
    update public.store_state set value=products,updated_at=now() where key='products';
  end if;
  update public.orders set status=p_status where reference=p_reference;
end; $$;
revoke all on function public.update_staff_order_status(text,text) from public,anon,authenticated;
grant execute on function public.update_staff_order_status(text,text) to authenticated;

-- Preserve all existing 10-argument callers. New frontend calls the overload above.
create or replace function public.create_store_order(p_cart jsonb,p_customer_name text,p_phone text,p_email text,p_address text,p_district text,p_division text,p_delivery_area text,p_payment_method text,p_coupon text)
returns jsonb language sql security definer set search_path = public as $$ select public.create_store_order($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,replace(gen_random_uuid()::text,'-','')); $$;
revoke all on function public.create_store_order(jsonb,text,text,text,text,text,text,text,text,text), public.create_store_order(jsonb,text,text,text,text,text,text,text,text,text,text) from public,anon,authenticated;
grant execute on function public.create_store_order(jsonb,text,text,text,text,text,text,text,text,text), public.create_store_order(jsonb,text,text,text,text,text,text,text,text,text,text) to service_role;
commit;
