-- Role-based access control for the SAZ admin panel.
-- Run this AFTER schema.sql and launch-hardening.sql in Supabase SQL Editor.
-- Existing legacy `admin` profiles are promoted to the protected Owner role.

begin;

create table if not exists public.access_roles (
  slug text primary key check (slug ~ '^[a-z0-9][a-z0-9-]{0,47}$'),
  name text not null check (char_length(name) between 2 and 80),
  description text not null default '' check (char_length(description) <= 240),
  permissions text[] not null default '{}'::text[],
  is_protected boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

insert into public.access_roles (slug, name, description, permissions, is_protected)
values
  ('owner', 'Owner', 'Full control of the store and access controls.', array['*'], true),
  ('administrator', 'Administrator', 'Runs the store day to day without changing team security.', array['admin.access','dashboard.view','orders.view','orders.manage','products.manage','coupons.manage','messages.view','messages.manage','content.manage','settings.manage','store.manage','customers.view'], false),
  ('manager', 'Store Manager', 'Oversees orders, catalog, promotions and store content.', array['admin.access','dashboard.view','orders.view','orders.manage','products.manage','coupons.manage','messages.view','content.manage','customers.view'], false),
  ('fulfillment', 'Fulfillment', 'Views and updates customer orders.', array['admin.access','dashboard.view','orders.view','orders.manage'], false),
  ('catalog-editor', 'Catalog Editor', 'Maintains products, collections and promotions.', array['admin.access','dashboard.view','products.manage','coupons.manage','content.manage'], false),
  ('support', 'Customer Support', 'Reads orders and handles customer messages.', array['admin.access','dashboard.view','orders.view','messages.view','messages.manage','customers.view'], false),
  ('marketing', 'Marketing', 'Edits storefront content and promotions.', array['admin.access','dashboard.view','content.manage','coupons.manage'], false),
  ('analyst', 'Analyst', 'Has read-only access to operational dashboards.', array['admin.access','dashboard.view','orders.view','messages.view','customers.view'], false),
  ('customer', 'Customer', 'Store customer account. No admin access.', array[]::text[], true)
on conflict (slug) do nothing;

-- The original schema used an enum with only customer and admin. Move to a
-- text role key so owners can create additional roles from the admin panel.
alter table public.profiles alter column role drop default;
alter table public.profiles alter column role type text using role::text;
alter table public.profiles alter column role set default 'customer';
alter table public.profiles add column if not exists is_active boolean not null default true;

update public.profiles set role = 'owner' where role = 'admin';
update public.profiles set role = 'customer'
where role not in (select slug from public.access_roles);

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'profiles_role_access_roles_fkey'
      and conrelid = 'public.profiles'::regclass
  ) then
    alter table public.profiles
      add constraint profiles_role_access_roles_fkey
      foreign key (role) references public.access_roles(slug)
      on update cascade;
  end if;
end $$;

create table if not exists public.admin_audit_log (
  id uuid primary key default gen_random_uuid(),
  actor_id uuid references auth.users(id) on delete set null,
  action text not null check (char_length(action) between 3 and 80),
  target_type text not null check (char_length(target_type) between 3 and 40),
  target_id text,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists admin_audit_log_created_at_idx
  on public.admin_audit_log (created_at desc);

alter table public.access_roles enable row level security;
alter table public.admin_audit_log enable row level security;

drop policy if exists "authenticated users can read access roles" on public.access_roles;
create policy "authenticated users can read access roles"
  on public.access_roles for select to authenticated using (true);

-- All role and staff mutations go through the manage-access Edge Function.
-- This prevents a browser from granting itself extra permissions directly.
revoke all on table public.access_roles, public.admin_audit_log from anon, authenticated;
grant select on table public.access_roles to authenticated;

create or replace function public.has_permission(required_permission text)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.profiles profile
    join public.access_roles role_definition on role_definition.slug = profile.role
    where profile.id = auth.uid()
      and profile.is_active
      and (
        role_definition.permissions @> array['*']::text[]
        or role_definition.permissions @> array[required_permission]::text[]
      )
  );
$$;

create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select public.has_permission('admin.access');
$$;

revoke all on function public.has_permission(text), public.is_admin() from public;
grant execute on function public.has_permission(text), public.is_admin() to authenticated;

-- These service-role-only functions enforce the last-active-Owner rule inside
-- one database transaction. The Edge Function performs its own Owner check
-- before calling them; browser clients receive no execute privilege.
create or replace function public.assign_profile_role(p_user_id uuid, p_role text)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  current_role text;
  current_active boolean;
  active_owner_count integer;
begin
  perform pg_advisory_xact_lock(hashtext('saz-owner-access-control'));
  if not exists (select 1 from public.access_roles where slug = p_role) then
    raise exception 'Choose a valid role.';
  end if;
  select role, is_active into current_role, current_active
    from public.profiles where id = p_user_id for update;
  if not found then raise exception 'That team member no longer exists.'; end if;
  if current_role = 'owner' and p_role <> 'owner' and current_active then
    select count(*) into active_owner_count from public.profiles
      where role = 'owner' and is_active;
    if active_owner_count <= 1 then
      raise exception 'At least one active Owner must always remain.';
    end if;
  end if;
  update public.profiles set role = p_role where id = p_user_id;
end;
$$;

create or replace function public.set_profile_active(p_user_id uuid, p_active boolean)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  current_role text;
  current_active boolean;
  active_owner_count integer;
begin
  perform pg_advisory_xact_lock(hashtext('saz-owner-access-control'));
  select role, is_active into current_role, current_active
    from public.profiles where id = p_user_id for update;
  if not found then raise exception 'That team member no longer exists.'; end if;
  if not p_active and current_active and current_role = 'owner' then
    select count(*) into active_owner_count from public.profiles
      where role = 'owner' and is_active;
    if active_owner_count <= 1 then
      raise exception 'The final active Owner cannot be suspended.';
    end if;
  end if;
  update public.profiles set is_active = p_active where id = p_user_id;
end;
$$;

revoke all on function public.assign_profile_role(uuid, text), public.set_profile_active(uuid, boolean) from public, anon, authenticated;
grant execute on function public.assign_profile_role(uuid, text), public.set_profile_active(uuid, boolean) to service_role;

drop policy if exists "profile owners can read themselves" on public.profiles;
create policy "profile owners can read themselves"
  on public.profiles for select using (id = auth.uid());

drop policy if exists "admins manage storefront state" on public.store_state;
drop policy if exists "authorized staff manage storefront state" on public.store_state;
create policy "authorized staff manage storefront state"
  on public.store_state for all
  using (
    public.has_permission('store.manage')
    or (key in ('products', 'product_types') and public.has_permission('products.manage'))
    or (key = 'coupons' and public.has_permission('coupons.manage'))
    or (key = 'settings' and public.has_permission('settings.manage'))
    or (key in ('site_content', 'page_products', 'home_categories') and public.has_permission('content.manage'))
  )
  with check (
    public.has_permission('store.manage')
    or (key in ('products', 'product_types') and public.has_permission('products.manage'))
    or (key = 'coupons' and public.has_permission('coupons.manage'))
    or (key = 'settings' and public.has_permission('settings.manage'))
    or (key in ('site_content', 'page_products', 'home_categories') and public.has_permission('content.manage'))
  );

drop policy if exists "admins manage orders" on public.orders;
drop policy if exists "staff can read orders" on public.orders;
drop policy if exists "staff can update orders" on public.orders;
drop policy if exists "staff can delete orders" on public.orders;
create policy "staff can read orders"
  on public.orders for select using (public.has_permission('orders.view'));
create policy "staff can update orders"
  on public.orders for update
  using (public.has_permission('orders.manage'))
  with check (public.has_permission('orders.manage'));
create policy "staff can delete orders"
  on public.orders for delete using (public.has_permission('orders.manage'));

-- Do not expose delivery/contact columns through direct table access. The
-- functions below return only what the caller's role may see or change.
revoke select, update, delete on table public.orders from anon, authenticated;

create or replace function public.list_staff_orders()
returns table (
  reference text,
  customer_name text,
  phone text,
  email text,
  address text,
  city text,
  district text,
  division text,
  payment_method text,
  subtotal numeric,
  shipping numeric,
  discount numeric,
  total numeric,
  coupon text,
  status text,
  line_items jsonb,
  created_at timestamptz
)
language sql
stable
security definer
set search_path = public
as $$
  select
    o.reference,
    case when public.has_permission('customers.view') then o.customer_name end,
    case when public.has_permission('customers.view') then o.phone end,
    case when public.has_permission('customers.view') then o.email end,
    case when public.has_permission('customers.view') then o.address end,
    case when public.has_permission('customers.view') then o.city end,
    case when public.has_permission('customers.view') then o.district end,
    case when public.has_permission('customers.view') then o.division end,
    o.payment_method, o.subtotal, o.shipping, o.discount, o.total, o.coupon,
    o.status, o.line_items, o.created_at
  from public.orders o
  where public.has_permission('orders.view')
  order by o.created_at desc
  limit 500;
$$;

create or replace function public.update_staff_order_status(p_reference text, p_status text)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if not public.has_permission('orders.manage') then
    raise exception 'You do not have permission to update orders.';
  end if;
  if p_status not in ('Processing', 'Shipped', 'Delivered', 'Cancelled') then
    raise exception 'Choose a valid order status.';
  end if;
  update public.orders set status = p_status where reference = p_reference;
  if not found then raise exception 'That order no longer exists.'; end if;
end;
$$;

revoke all on function public.list_staff_orders(), public.update_staff_order_status(text, text) from public, anon, authenticated;
grant execute on function public.list_staff_orders(), public.update_staff_order_status(text, text) to authenticated;

drop policy if exists "admins manage contact messages" on public.contact_messages;
drop policy if exists "staff can read contact messages" on public.contact_messages;
drop policy if exists "staff can update contact messages" on public.contact_messages;
drop policy if exists "staff can delete contact messages" on public.contact_messages;
create policy "staff can read contact messages"
  on public.contact_messages for select using (public.has_permission('messages.view'));
create policy "staff can update contact messages"
  on public.contact_messages for update
  using (public.has_permission('messages.manage'))
  with check (public.has_permission('messages.manage'));
create policy "staff can delete contact messages"
  on public.contact_messages for delete using (public.has_permission('messages.manage'));
grant select, update, delete on table public.contact_messages to authenticated;

commit;
