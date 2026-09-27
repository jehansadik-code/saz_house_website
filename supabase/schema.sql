-- Run this once in Supabase Dashboard > SQL Editor. It is safe to run again.
create extension if not exists pgcrypto;

do $$ begin
  create type public.app_role as enum ('customer', 'admin');
exception when duplicate_object then null;
end $$;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  role public.app_role not null default 'customer',
  created_at timestamptz not null default now()
);

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id) values (new.id) on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
for each row execute procedure public.handle_new_user();

create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin');
$$;

create table if not exists public.store_state (
  key text primary key check (key in ('products','product_types','coupons','settings','site_content','page_products','home_categories')),
  value jsonb not null,
  updated_at timestamptz not null default now()
);

create table if not exists public.orders (
  id uuid primary key default gen_random_uuid(),
  reference text not null unique,
  customer_name text, phone text, email text, address text, city text, district text, division text,
  payment_method text, subtotal numeric(12,2) not null default 0, shipping numeric(12,2) not null default 0,
  discount numeric(12,2) not null default 0, total numeric(12,2) not null default 0,
  coupon text, status text not null default 'Processing' check (status in ('Processing','Shipped','Delivered','Cancelled')),
  line_items jsonb not null default '[]'::jsonb, created_at timestamptz not null default now()
);

create table if not exists public.contact_messages (
  id text primary key, name text not null, email text not null, subject text, message text not null,
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;
alter table public.store_state enable row level security;
alter table public.orders enable row level security;
alter table public.contact_messages enable row level security;

drop policy if exists "profile owners can read themselves" on public.profiles;
create policy "profile owners can read themselves" on public.profiles for select using (id = auth.uid() or public.is_admin());
drop policy if exists "public can read storefront state" on public.store_state;
create policy "public can read storefront state" on public.store_state for select using (true);
drop policy if exists "admins manage storefront state" on public.store_state;
create policy "admins manage storefront state" on public.store_state for all using (public.is_admin()) with check (public.is_admin());
drop policy if exists "customers can place orders" on public.orders;
create policy "customers can place orders" on public.orders for insert with check (true);
drop policy if exists "admins manage orders" on public.orders;
create policy "admins manage orders" on public.orders for all using (public.is_admin()) with check (public.is_admin());
drop policy if exists "visitors can send contact messages" on public.contact_messages;
create policy "visitors can send contact messages" on public.contact_messages for insert with check (true);
drop policy if exists "admins manage contact messages" on public.contact_messages;
create policy "admins manage contact messages" on public.contact_messages for all using (public.is_admin()) with check (public.is_admin());

  -- After creating your own Supabase account, run this once with your actual email:
  -- update public.profiles p set role = 'admin' from auth.users u where p.id = u.id and u.email = 'you@example.com';
