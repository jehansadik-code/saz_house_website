-- Read-only checkout compatibility diagnostic. Safe to run in Supabase SQL Editor.
-- It verifies that the simplified checkout form can omit email, district, and division.

select
  column_name,
  data_type,
  is_nullable
from information_schema.columns
where table_schema = 'public'
  and table_name = 'orders'
  and column_name in ('customer_name', 'phone', 'email', 'address', 'city', 'district', 'division', 'payment_method')
order by ordinal_position;

select
  p.proname,
  p.pronargs as input_count,
  p.proargnames as argument_names,
  p.oid::regprocedure as signature,
  has_function_privilege('service_role', p.oid, 'EXECUTE') as service_role_can_execute
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
where n.nspname = 'public'
  and p.proname in ('create_store_order', 'take_submission_slot', 'update_staff_order_status')
order by p.proname, p.pronargs;

select
  c.relname as table_name,
  c.relrowsecurity as rls_enabled,
  has_table_privilege('anon', c.oid, 'SELECT') as anon_can_select,
  has_table_privilege('authenticated', c.oid, 'SELECT') as authenticated_can_select
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public'
  and c.relname in ('orders', 'checkout_requests', 'submission_throttle')
order by c.relname;
