import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const PUBLIC_SITE_URL = (Deno.env.get("PUBLIC_SITE_URL") || "").replace(/\/$/, "");
const ALLOWED_ORIGINS = new Set(
  (Deno.env.get("ALLOWED_ORIGINS") || PUBLIC_SITE_URL)
    .split(",")
    .map((origin) => origin.trim().replace(/\/$/, ""))
    .filter(Boolean)
);
const service = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false }
});

const PERMISSIONS = new Set([
  "admin.access",
  "dashboard.view",
  "orders.view",
  "orders.manage",
  "products.manage",
  "coupons.manage",
  "messages.view",
  "messages.manage",
  "content.manage",
  "settings.manage",
  "store.manage",
  "customers.view"
]);
const PERMISSION_DEPENDENCIES: Record<string, string[]> = {
  "orders.manage": ["orders.view"],
  "customers.view": ["orders.view"],
  "messages.manage": ["messages.view"]
};

type AccessRole = {
  slug: string;
  name: string;
  description: string;
  permissions: string[];
  is_protected: boolean;
};

const originFor = (request: Request) => request.headers.get("origin") || "";
const allowedOrigin = (request: Request) => {
  const origin = originFor(request);
  return !origin || ALLOWED_ORIGINS.has(origin);
};
const headers = (request: Request) => ({
  "Access-Control-Allow-Origin": allowedOrigin(request) ? (originFor(request) || PUBLIC_SITE_URL) : PUBLIC_SITE_URL,
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json",
  "Vary": "Origin"
});
const respond = (request: Request, status: number, body: Record<string, unknown>) =>
  new Response(JSON.stringify(body), { status, headers: headers(request) });
const safeText = (value: unknown, limit: number) => String(value ?? "").trim().slice(0, limit);
const safeEmail = (value: unknown) => {
  const email = safeText(value, 254).toLowerCase();
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ? email : "";
};
const slugify = (value: string) => value.toLowerCase()
  .replace(/[^a-z0-9]+/g, "-")
  .replace(/^-+|-+$/g, "")
  .slice(0, 48);

async function actorFor(request: Request) {
  const token = request.headers.get("authorization")?.replace(/^Bearer\s+/i, "");
  if (!token) return { error: "Sign in is required." };

  const { data, error } = await service.auth.getUser(token);
  const user = data.user;
  if (error || !user) return { error: "Your session is invalid or has expired." };

  const { data: profile, error: profileError } = await service
    .from("profiles")
    .select("role,is_active")
    .eq("id", user.id)
    .maybeSingle();
  if (profileError || !profile || !profile.is_active) return { error: "Your access profile is unavailable." };

  const { data: role, error: roleError } = await service
    .from("access_roles")
    .select("slug,name,description,permissions,is_protected")
    .eq("slug", profile.role)
    .maybeSingle();
  if (roleError || !role) return { error: "Your assigned role is unavailable." };
  if (role.slug !== "owner") return { error: "Only an Owner can manage staff access." };

  return { user, role: role as AccessRole };
}

async function logAction(actorId: string, action: string, targetType: string, targetId: string | null, details: Record<string, unknown> = {}) {
  await service.from("admin_audit_log").insert({
    actor_id: actorId,
    action,
    target_type: targetType,
    target_id: targetId,
    details
  });
}

async function allRoles() {
  const { data, error } = await service
    .from("access_roles")
    .select("slug,name,description,permissions,is_protected,created_at,updated_at")
    .order("is_protected", { ascending: false })
    .order("name");
  if (error) throw new Error(error.message);
  return data || [];
}

async function allStaff() {
  const { data: authData, error: authError } = await service.auth.admin.listUsers({ page: 1, perPage: 1000 });
  if (authError) throw new Error(authError.message);
  const users = authData.users || [];
  const { data: profiles, error: profilesError } = await service
    .from("profiles")
    .select("id,role,is_active,created_at")
    .in("id", users.map((user) => user.id));
  if (profilesError) throw new Error(profilesError.message);
  const roles = new Map((profiles || []).map((profile) => [profile.id, profile]));

  return users.map((user) => {
    const profile = roles.get(user.id);
    return {
      id: user.id,
      email: user.email || "",
      role: profile?.role || "customer",
      is_active: profile?.is_active === true,
      created_at: profile?.created_at || user.created_at,
      last_sign_in_at: user.last_sign_in_at || null,
      banned_until: user.banned_until || null
    };
  }).sort((a, b) => a.email.localeCompare(b.email));
}

async function dashboard() {
  const [roles, staff, logsResult] = await Promise.all([
    allRoles(),
    allStaff(),
    service
      .from("admin_audit_log")
      .select("id,action,target_type,target_id,details,created_at")
      .order("created_at", { ascending: false })
      .limit(20)
  ]);
  if (logsResult.error) throw new Error(logsResult.error.message);
  return { roles, staff, audit: logsResult.data || [] };
}

async function saveRole(input: Record<string, unknown>, actorId: string) {
  const requestedSlug = safeText(input.slug, 48);
  const name = safeText(input.name, 80);
  const description = safeText(input.description, 240);
  const permissions = [...new Set(Array.isArray(input.permissions) ? input.permissions.filter((value): value is string => typeof value === "string" && PERMISSIONS.has(value)) : [])];
  if (name.length < 2) throw new Error("A role name must have at least two characters.");
  if (!permissions.includes("admin.access")) throw new Error("Every staff role must include Admin panel access.");
  for (const [permission, dependencies] of Object.entries(PERMISSION_DEPENDENCIES)) {
    if (permissions.includes(permission) && dependencies.some((dependency) => !permissions.includes(dependency))) {
      throw new Error(`${permission} requires ${dependencies.join(" and ")}.`);
    }
  }

  if (requestedSlug) {
    const { data: existing, error } = await service
      .from("access_roles")
      .select("slug,is_protected")
      .eq("slug", requestedSlug)
      .maybeSingle();
    if (error || !existing) throw new Error("That role no longer exists.");
    if (existing.is_protected) throw new Error("Protected Owner and Customer roles cannot be edited.");
    const { error: updateError } = await service
      .from("access_roles")
      .update({ name, description, permissions, updated_at: new Date().toISOString() })
      .eq("slug", requestedSlug);
    if (updateError) throw new Error(updateError.message);
    await logAction(actorId, "role.updated", "role", requestedSlug, { name, permissions });
    return;
  }

  const slug = slugify(name);
  if (slug.length < 2) throw new Error("Use letters or numbers in the role name.");
  const { error } = await service.from("access_roles").insert({ slug, name, description, permissions });
  if (error) throw new Error(error.code === "23505" ? "A role with that name already exists." : error.message);
  await logAction(actorId, "role.created", "role", slug, { name, permissions });
}

async function deleteRole(input: Record<string, unknown>, actorId: string) {
  const slug = safeText(input.slug, 48);
  const { data: role, error } = await service
    .from("access_roles")
    .select("slug,is_protected")
    .eq("slug", slug)
    .maybeSingle();
  if (error || !role) throw new Error("That role no longer exists.");
  if (role.is_protected) throw new Error("Protected roles cannot be deleted.");
  const { count, error: countError } = await service
    .from("profiles")
    .select("id", { count: "exact", head: true })
    .eq("role", slug);
  if (countError) throw new Error(countError.message);
  if (count) throw new Error("Move every team member to another role before deleting this role.");
  const { error: deleteError } = await service.from("access_roles").delete().eq("slug", slug);
  if (deleteError) throw new Error(deleteError.message);
  await logAction(actorId, "role.deleted", "role", slug);
}

async function assignRole(input: Record<string, unknown>, actorId: string) {
  const userId = safeText(input.userId, 36);
  const role = safeText(input.role, 48);
  const { data: target, error: targetError } = await service
    .from("profiles")
    .select("id,role")
    .eq("id", userId)
    .maybeSingle();
  if (targetError || !target) throw new Error("That team member no longer exists.");
  const { data: destination, error: destinationError } = await service
    .from("access_roles")
    .select("slug")
    .eq("slug", role)
    .maybeSingle();
  if (destinationError || !destination) throw new Error("Choose a valid role.");
  const { error } = await service.rpc("assign_profile_role", { p_user_id: userId, p_role: role });
  if (error) throw new Error(error.message);
  await logAction(actorId, "staff.role_changed", "user", userId, { from: target.role, to: role });
}

function passwordFrom(input: Record<string, unknown>) {
  return typeof input.password === "string" ? input.password : "";
}

function validatePassword(password: string) {
  if (password.length < 12 || password.length > 128) {
    throw new Error("Use a password between 12 and 128 characters.");
  }
  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/\d/.test(password)) {
    throw new Error("Use uppercase, lowercase, and at least one number in the password.");
  }
}

async function validStaffRole(role: string) {
  const { data, error } = await service.from("access_roles").select("slug").eq("slug", role).maybeSingle();
  if (error || !data || role === "customer") throw new Error("Choose a valid staff role.");
}

async function createStaff(input: Record<string, unknown>, actorId: string) {
  const email = safeEmail(input.email);
  const role = safeText(input.role, 48);
  const password = passwordFrom(input);
  if (!email) throw new Error("Enter a valid staff email address.");
  validatePassword(password);
  await validStaffRole(role);
  const { data, error } = await service.auth.admin.createUser({ email, password, email_confirm: true });
  if (error || !data.user) throw new Error(error?.message || "Could not create that employee account.");
  const { error: profileError } = await service
    .from("profiles")
    .update({ role, is_active: true })
    .eq("id", data.user.id);
  if (profileError) throw new Error(profileError.message);
  await logAction(actorId, "staff.created", "user", data.user.id, { email, role });
}

async function setStaffPassword(input: Record<string, unknown>, actorId: string) {
  const userId = safeText(input.userId, 36);
  const password = passwordFrom(input);
  validatePassword(password);
  const { data, error } = await service.auth.admin.getUserById(userId);
  if (error || !data.user) throw new Error("That team member no longer exists.");
  const { error: updateError } = await service.auth.admin.updateUserById(userId, { password });
  if (updateError) throw new Error(updateError.message);
  await logAction(actorId, "staff.password_changed", "user", userId);
}

async function setStatus(input: Record<string, unknown>, actorId: string) {
  const userId = safeText(input.userId, 36);
  const active = input.active === true;
  const { error: profileError } = await service.rpc("set_profile_active", { p_user_id: userId, p_active: active });
  if (profileError) throw new Error(profileError.message);
  const { error } = await service.auth.admin.updateUserById(userId, { ban_duration: active ? "none" : "876000h" });
  if (error) {
    await service.rpc("set_profile_active", { p_user_id: userId, p_active: !active });
    throw new Error(error.message);
  }
  await logAction(actorId, active ? "staff.activated" : "staff.suspended", "user", userId);
}

Deno.serve(async (request) => {
  if (!allowedOrigin(request)) return respond(request, 403, { error: "This origin is not allowed." });
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: headers(request) });
  if (request.method !== "POST") return respond(request, 405, { error: "Method not allowed." });

  try {
    const body = await request.json();
    const action = safeText(body?.action, 32);
    const actor = await actorFor(request);
    if ("error" in actor) return respond(request, 403, { error: actor.error });

    if (action === "overview") return respond(request, 200, { data: await dashboard() });
    if (action === "save_role") await saveRole(body, actor.user.id);
    else if (action === "delete_role") await deleteRole(body, actor.user.id);
    else if (action === "assign_role") await assignRole(body, actor.user.id);
    else if (action === "create_staff") await createStaff(body, actor.user.id);
    else if (action === "set_staff_password") await setStaffPassword(body, actor.user.id);
    else if (action === "set_status") await setStatus(body, actor.user.id);
    else return respond(request, 400, { error: "Unknown access-control action." });

    return respond(request, 200, { data: await dashboard() });
  } catch (error) {
    console.error("manage-access error", error);
    return respond(request, 400, { error: error instanceof Error ? error.message : "Access control request failed." });
  }
});
