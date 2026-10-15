-- Read-only post-deployment checks for the SAZ role and data-access model.
-- Run in Supabase SQL Editor after schema.sql, launch-hardening.sql and access-control.sql.

-- 1. RLS must be enabled on every protected table.
select schemaname, tablename, rowsecurity as rls_enabled
from pg_tables
where schemaname = 'public'
  and tablename in ('profiles', 'access_roles', 'admin_audit_log', 'store_state', 'orders', 'contact_messages', 'submission_throttle')
order by tablename;

-- 2. Inspect active policies and ensure no old broad admin policy survived.
select tablename, policyname, cmd, roles, qual, with_check
from pg_policies
where schemaname = 'public'
  and tablename in ('profiles', 'access_roles', 'admin_audit_log', 'store_state', 'orders', 'contact_messages', 'submission_throttle')
order by tablename, policyname;

-- 3. Orders must not have direct authenticated SELECT/UPDATE/DELETE grants.
select grantee, privilege_type
from information_schema.role_table_grants
where table_schema = 'public'
  and table_name = 'orders'
  and grantee in ('anon', 'authenticated')
order by grantee, privilege_type;

-- 4. The safe order RPCs and protected role RPCs must exist.
select routine_name, security_type
from information_schema.routines
where routine_schema = 'public'
  and routine_name in ('has_permission', 'is_admin', 'assign_profile_role', 'set_profile_active', 'list_staff_orders', 'update_staff_order_status')
order by routine_name;

-- 5. Review roles and their permissions. Only Owner should normally contain '*'.
select slug, name, permissions, is_protected, created_at, updated_at
from public.access_roles
order by is_protected desc, name;

-- 6. Confirm there is at least one active Owner before changing roles.
select count(*) as active_owner_count
from public.profiles
where role = 'owner' and is_active;

-- 7. Review role/security events. Password values are intentionally never logged.
select action, target_type, target_id, details, created_at
from public.admin_audit_log
order by created_at desc
limit 100;
