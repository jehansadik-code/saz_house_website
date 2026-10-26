-- Run after variant-inventory.sql and access-control.sql.
-- Inventory is reserved when an order is placed. Cancelling returns the exact
-- colour/size quantities; moving a cancelled order back to active reserves them again.
create or replace function public.update_staff_order_status(p_reference text, p_status text)
returns void language plpgsql security definer set search_path = public as $$
declare
  current_status text; order_lines jsonb; products jsonb; line jsonb; product jsonb;
  item_index bigint; variant_index bigint; variants jsonb; stock integer; quantity integer;
  direction integer;
begin
  if not public.has_permission('orders.manage') then raise exception 'You do not have permission to update orders.'; end if;
  if p_status not in ('Processing', 'Shipped', 'Delivered', 'Cancelled') then raise exception 'Choose a valid order status.'; end if;
  select status, line_items into current_status, order_lines from public.orders where reference=p_reference for update;
  if not found then raise exception 'That order no longer exists.'; end if;
  if current_status=p_status then return; end if;
  if current_status='Cancelled' or p_status='Cancelled' then
    direction:=case when p_status='Cancelled' then 1 else -1 end;
    select value into products from public.store_state where key='products' for update;
    for line in select value from jsonb_array_elements(coalesce(order_lines,'[]'::jsonb)) loop
      quantity:=greatest(0,coalesce(nullif(line->>'qty','')::integer,0));
      select value, ordinality-1 into product, item_index from jsonb_array_elements(products) with ordinality where value->>'id'=line->>'id' limit 1;
      if product is null then continue; end if;
      if jsonb_typeof(product->'variants')='array' and jsonb_array_length(product->'variants')>0 then
        variants:=product->'variants';
        select value, ordinality-1 into product, variant_index from jsonb_array_elements(variants) with ordinality where value->>'color'=line->>'color' and value->>'size'=line->>'size' limit 1;
        if product is null then raise exception 'The ordered variant no longer exists.'; end if;
        stock:=coalesce(nullif(product->>'stock','')::integer,0);
        if direction=-1 and stock<quantity then raise exception 'Insufficient stock to reactivate this order.'; end if;
        variants:=jsonb_set(variants,array[variant_index::text,'stock'],to_jsonb(greatest(0,stock+direction*quantity)),false);
        products:=jsonb_set(products,array[item_index::text,'variants'],variants,false);
        products:=jsonb_set(products,array[item_index::text,'stock'],to_jsonb((select coalesce(sum(coalesce(nullif(value->>'stock','')::integer,0)),0) from jsonb_array_elements(variants))),false);
      else
        stock:=coalesce(nullif(product->>'stock','')::integer,0);
        if direction=-1 and stock<quantity then raise exception 'Insufficient stock to reactivate this order.'; end if;
        products:=jsonb_set(products,array[item_index::text,'stock'],to_jsonb(greatest(0,stock+direction*quantity)),false);
      end if;
    end loop;
    update public.store_state set value=products,updated_at=now() where key='products';
  end if;
  update public.orders set status=p_status where reference=p_reference;
end; $$;

revoke all on function public.update_staff_order_status(text,text) from public, anon, authenticated;
grant execute on function public.update_staff_order_status(text,text) to authenticated;
