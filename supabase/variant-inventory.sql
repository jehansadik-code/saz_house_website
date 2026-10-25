-- Run after launch-hardening.sql. Product state stores variants as:
-- { "color": "Black", "size": "M", "stock": 12 }.
-- Older products without variants retain one shared stock pool across their options.

create or replace function public.create_store_order(
  p_cart jsonb, p_customer_name text, p_phone text, p_email text, p_address text,
  p_district text, p_division text, p_delivery_area text, p_payment_method text, p_coupon text
) returns jsonb language plpgsql security definer set search_path = public as $$
declare
  products jsonb; settings jsonb; coupons jsonb; cart_item jsonb; product jsonb; coupon jsonb;
  item_index bigint; quantity integer; stock integer; unit_price numeric(12,2);
  variant_index bigint; variants jsonb; selected_color text; selected_size text; product_name text; selected_product jsonb;
  subtotal numeric(12,2):=0; shipping numeric(12,2):=0; discount numeric(12,2):=0; order_total numeric(12,2):=0;
  line_items jsonb:='[]'::jsonb; reference_code text:='SAZ-'||upper(substr(replace(gen_random_uuid()::text,'-',''),1,10)); status_value text:='Processing';
begin
  if jsonb_typeof(p_cart)<>'array' or jsonb_array_length(p_cart)=0 or jsonb_array_length(p_cart)>25 then raise exception 'Your cart is invalid.'; end if;
  if char_length(trim(coalesce(p_customer_name,''))) not between 1 and 100 or char_length(trim(coalesce(p_phone,''))) not between 7 and 30 or char_length(trim(coalesce(p_address,''))) not between 5 and 500 then raise exception 'Please provide valid delivery details.'; end if;
  if p_payment_method not in ('Cash on Delivery','bKash','Nagad','Card (demo)') then raise exception 'Invalid payment method.'; end if;
  select value into products from public.store_state where key='products' for update;
  select value into settings from public.store_state where key='settings'; select value into coupons from public.store_state where key='coupons';
  if products is null or settings is null then raise exception 'Store is not ready.'; end if;
  for cart_item in select value from jsonb_array_elements(p_cart) loop
    quantity:=coalesce(nullif(cart_item->>'qty','')::integer,0); selected_color:=left(trim(coalesce(cart_item->>'color','')),60); selected_size:=left(trim(coalesce(cart_item->>'size','')),30);
    if quantity<1 or quantity>20 or coalesce(cart_item->>'id','') !~ '^[a-zA-Z0-9_-]{1,100}$' or selected_color='' or selected_size='' then raise exception 'Invalid cart item.'; end if;
    select value,ordinality-1 into product,item_index from jsonb_array_elements(products) with ordinality where value->>'id'=cart_item->>'id' and coalesce((value->>'active')::boolean,true) limit 1;
    if product is null then raise exception 'A product is no longer available.'; end if; selected_product:=product; product_name:=left(coalesce(product->>'name',''),160);
    unit_price:=coalesce(nullif(product->>'price','')::numeric,-1); if unit_price<0 then raise exception 'Invalid product price.'; end if;
    if jsonb_typeof(product->'variants')='array' and jsonb_array_length(product->'variants')>0 then
      variants:=product->'variants'; select value,ordinality-1 into product,variant_index from jsonb_array_elements(variants) with ordinality where value->>'color'=selected_color and value->>'size'=selected_size limit 1;
      if product is null then raise exception 'This colour and size is unavailable.'; end if;
      stock:=coalesce(nullif(product->>'stock','')::integer,0); if stock<quantity then raise exception 'Insufficient stock for this colour and size.'; end if;
      variants:=jsonb_set(variants,array[variant_index::text,'stock'],to_jsonb(stock-quantity),false);
      products:=jsonb_set(products,array[item_index::text,'variants'],variants,false);
      products:=jsonb_set(products,array[item_index::text,'stock'],to_jsonb((select coalesce(sum(coalesce(nullif(value->>'stock','')::integer,0)),0) from jsonb_array_elements(variants))),false);
    else
      if not exists(select 1 from jsonb_array_elements_text(case when jsonb_typeof(selected_product->'colors')='array' and jsonb_array_length(selected_product->'colors')>0 then selected_product->'colors' else jsonb_build_array(coalesce(selected_product->>'color','Black')) end) as colors(value) where colors.value=selected_color)
         or not exists(select 1 from jsonb_array_elements_text(case when jsonb_typeof(selected_product->'sizes')='array' and jsonb_array_length(selected_product->'sizes')>0 then selected_product->'sizes' else '["One Size"]'::jsonb end) as sizes(value) where sizes.value=selected_size) then raise exception 'This colour and size is unavailable.'; end if;
      stock:=coalesce(nullif(product->>'stock','')::integer,0); if stock<quantity then raise exception 'Insufficient stock.'; end if;
      products:=jsonb_set(products,array[item_index::text,'stock'],to_jsonb(stock-quantity),false);
    end if;
    subtotal:=subtotal+unit_price*quantity; line_items:=line_items||jsonb_build_array(jsonb_build_object('id',cart_item->>'id','name',product_name,'color',selected_color,'size',selected_size,'qty',quantity,'price',unit_price));
  end loop;
  if p_delivery_area='dhaka' then shipping:=coalesce(nullif(settings->>'dhaka','')::numeric,0); elsif p_delivery_area='outside' then shipping:=coalesce(nullif(settings->>'outside','')::numeric,0); else raise exception 'Select a delivery area.'; end if;
  if coalesce(nullif(settings->>'freeThreshold','')::numeric,0)>0 and subtotal>=(settings->>'freeThreshold')::numeric then shipping:=0; end if;
  if p_coupon is not null and trim(p_coupon)<>'' then select value into coupon from jsonb_array_elements(coalesce(coupons,'[]'::jsonb)) where upper(value->>'code')=upper(trim(p_coupon)) and coalesce((value->>'active')::boolean,false) and subtotal>=coalesce(nullif(value->>'minimum','')::numeric,0) limit 1; if coupon is null then raise exception 'Coupon is invalid.'; end if; discount:=case when coupon->>'type'='percent' then least(subtotal,round(subtotal*coalesce(nullif(coupon->>'value','')::numeric,0)/100)) else least(subtotal,coalesce(nullif(coupon->>'value','')::numeric,0)) end; end if;
  order_total:=greatest(0,subtotal+shipping-discount); update public.store_state set value=products,updated_at=now() where key='products';
  insert into public.orders(reference,customer_name,phone,email,address,city,district,division,payment_method,subtotal,shipping,discount,total,coupon,status,line_items) values(reference_code,trim(p_customer_name),trim(p_phone),nullif(trim(p_email),''),trim(p_address),case when p_delivery_area='dhaka' then 'Dhaka' else 'Outside Dhaka' end,nullif(trim(p_district),''),nullif(trim(p_division),''),p_payment_method,subtotal,shipping,discount,order_total,nullif(upper(trim(p_coupon),''),''),status_value,line_items);
  return jsonb_build_object('ref',reference_code,'total',order_total,'status',status_value);
end; $$;

revoke all on function public.create_store_order(jsonb,text,text,text,text,text,text,text,text,text) from public,anon,authenticated;
grant execute on function public.create_store_order(jsonb,text,text,text,text,text,text,text,text,text) to service_role;
