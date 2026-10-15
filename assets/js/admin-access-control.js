/* Owner-only roles and direct employee account controls for the SAZ admin panel. */
(() => {
  'use strict';

  const permissionGroups = [
    {
      label: 'Workspace',
      items: [
        ['admin.access', 'Admin panel access', 'Allows this role to sign in to the admin portal.'],
        ['dashboard.view', 'Dashboard', 'See the store overview and statistics.']
      ]
    },
    {
      label: 'Sales',
      items: [
        ['orders.view', 'View orders', 'Read order totals, items, payment and fulfillment status.'],
        ['orders.manage', 'Manage orders', 'Update fulfillment status or remove orders.'],
        ['customers.view', 'Customer details', 'View customer information attached to orders.']
      ]
    },
    {
      label: 'Store operations',
      items: [
        ['products.manage', 'Products and categories', 'Create, edit and remove catalog items.'],
        ['coupons.manage', 'Coupons', 'Create, edit and remove promotions.'],
        ['messages.view', 'View messages', 'Read customer contact messages.'],
        ['messages.manage', 'Manage messages', 'Update or remove customer messages.'],
        ['content.manage', 'Site content', 'Edit homepage, slideshow and page content.'],
        ['settings.manage', 'Store settings', 'Change delivery and payment settings.'],
        ['store.manage', 'Full store data', 'Manage every store-data section and backups. Use only for trusted administrators.']
      ]
    }
  ];
  const viewPermissions = {
    Overview: 'dashboard.view',
    Statistics: 'dashboard.view',
    Orders: 'orders.view',
    Products: 'products.manage',
    Coupons: 'coupons.manage',
    Messages: 'messages.view',
    Settings: 'settings.manage',
    'Home categories': 'content.manage',
    'Homepage slideshow': 'content.manage',
    'Site Content': 'content.manage',
    'Page products': 'content.manage'
  };
  const storeScopedPermissions = new Set(['products.manage', 'coupons.manage', 'content.manage', 'settings.manage']);
  const actionPermissions = {
    'product-new': 'products.manage',
    'product-edit': 'products.manage',
    'product-delete': 'products.manage',
    'coupon-new': 'coupons.manage',
    'coupon-edit': 'coupons.manage',
    'coupon-delete': 'coupons.manage',
    'order-status': 'orders.manage',
    'admin-export': 'store.manage',
    'admin-import': 'store.manage'
  };
  const formPermissions = {
    'settings-form': 'settings.manage',
    'site-content-form': 'content.manage',
    'home-categories-form': 'content.manage',
    'home-slideshow-form': 'content.manage',
    'page-products-form': 'content.manage',
    'product-form': 'products.manage',
    'product-type-form': 'products.manage',
    'coupon-form': 'coupons.manage'
  };
  let state = null;
  let roleEditor = null;
  let passwordEditor = null;
  let booted = false;
  let requested = false;

  const escapeHtml = (value) => String(value ?? '').replace(/[&<>'"]/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
  })[character]);
  const notify = (message) => window.toast ? window.toast(message) : window.alert(message);
  const rawCan = (permission) => window.SAZ_SUPABASE?.hasPermission?.(permission) === true;
  const can = (permission) => rawCan(permission) || (storeScopedPermissions.has(permission) && rawCan('store.manage'));
  const isOwner = () => window.SAZ_SUPABASE?.getRole?.()?.slug === 'owner';
  const formatDate = (value) => value ? new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)) : 'Never';
  const roleBySlug = (slug) => state?.roles?.find((role) => role.slug === slug);
  const labelForRole = (slug) => roleBySlug(slug)?.name || slug;

  function addNav() {
    const sidebar = document.querySelector('.admin-sidebar');
    if (!sidebar || sidebar.querySelector('[data-access-tab]')) return;
    const section = document.createElement('div');
    section.className = 'admin-access-nav';
    section.innerHTML = '<div class="admin-nav-label">ACCESS</div><button class="admin-nav" type="button" data-access-tab><span>◉</span> Access control</button>';
    sidebar.insertBefore(section, sidebar.querySelector('.admin-sidebar-bottom'));
  }

  function applyNavigationPermissions() {
    document.querySelectorAll('.admin-nav[data-view]').forEach((button) => {
      const required = viewPermissions[button.dataset.view];
      button.hidden = Boolean(required && !can(required));
    });
    const accessNav = document.querySelector('[data-access-tab]');
    if (accessNav) accessNav.closest('.admin-access-nav').hidden = !isOwner();
    const role = window.SAZ_SUPABASE?.getRole?.();
    const status = document.querySelector('.admin-live');
    const label = role ? escapeHtml(role.name || role.slug).toUpperCase() : '';
    if (status && label && status.dataset.accessRoleLabel !== label) {
      status.dataset.accessRoleLabel = label;
      status.innerHTML = `<i></i> ${label}`;
    }
    applyWorkspacePermissions();
    const active = document.querySelector('.admin-nav.active[data-view]');
    if (active?.hidden) {
      const firstAllowed = [...document.querySelectorAll('.admin-nav[data-view]')].find((button) => !button.hidden);
      if (firstAllowed) queueMicrotask(() => firstAllowed.click());
    }
  }

  function showDenied(workspace) {
    workspace.innerHTML = '<div class="admin-empty-card">You do not have permission to view this admin section.</div>';
  }

  function applyWorkspacePermissions() {
    const workspace = document.getElementById('admin-workspace');
    if (!workspace) return;
    workspace.querySelectorAll('[data-action="admin-tab"][data-view]').forEach((button) => {
      const required = viewPermissions[button.dataset.view];
      button.hidden = Boolean(required && !can(required));
    });
    workspace.querySelectorAll('[data-action]').forEach((control) => {
      const required = actionPermissions[control.dataset.action];
      if (!required || can(required)) return;
      if (control.dataset.action === 'order-status' && control instanceof HTMLSelectElement) {
        control.replaceWith(document.createTextNode(control.value));
      } else {
        control.hidden = true;
      }
    });
    for (const [formId, permission] of Object.entries(formPermissions)) {
      const form = workspace.querySelector(`#${formId}`);
      if (!form || can(permission)) continue;
      const modal = form.closest('.admin-modal-backdrop');
      if (modal) modal.remove();
      else showDenied(workspace);
      return;
    }
  }

  function roleOptions(selected, { includeCustomer = true } = {}) {
    return (state?.roles || []).filter((role) => includeCustomer || role.slug !== 'customer').map((role) =>
      `<option value="${escapeHtml(role.slug)}" ${role.slug === selected ? 'selected' : ''}>${escapeHtml(role.name)}</option>`
    ).join('');
  }

  function statusFor(member) {
    return !member.is_active || (member.banned_until && new Date(member.banned_until).getTime() > Date.now())
      ? '<span class="access-status suspended">Suspended</span>'
      : '<span class="access-status active">Active</span>';
  }

  function teamRows() {
    const members = (state?.staff || []).filter((member) => member.role !== 'customer');
    if (!members.length) return '<tr><td colspan="5" class="admin-empty">No staff accounts yet. Create your first team member above.</td></tr>';
    return members.map((member) => {
      const suspended = !member.is_active || (member.banned_until && new Date(member.banned_until).getTime() > Date.now());
      return `<tr>
        <td><b>${escapeHtml(member.email)}</b><small>Added ${escapeHtml(formatDate(member.created_at))}</small></td>
        <td><select class="access-role-select" data-member-id="${escapeHtml(member.id)}" aria-label="Role for ${escapeHtml(member.email)}">${roleOptions(member.role)}</select></td>
        <td>${statusFor(member)}</td>
        <td><small>${escapeHtml(formatDate(member.last_sign_in_at))}</small></td>
        <td class="access-row-actions">
          <button type="button" data-access-action="set-password" data-member-id="${escapeHtml(member.id)}">Set password</button>
          <button type="button" data-access-action="toggle-status" data-member-id="${escapeHtml(member.id)}" data-active="${suspended ? 'true' : 'false'}">${suspended ? 'Activate' : 'Suspend'}</button>
        </td>
      </tr>`;
    }).join('');
  }

  function roleCards() {
    return (state?.roles || []).map((role) => {
      const protectedRole = role.is_protected;
      const count = (state.staff || []).filter((member) => member.role === role.slug).length;
      const permissions = role.permissions?.includes('*') ? 'All permissions' : `${role.permissions?.length || 0} permissions`;
      return `<article class="access-role-card">
        <div><span class="access-role-title">${escapeHtml(role.name)}</span>${protectedRole ? '<span class="access-lock">Protected</span>' : ''}<p>${escapeHtml(role.description || 'No description added.')}</p></div>
        <small>${count} assigned · ${permissions}</small>
        <div class="access-role-actions">
          <button type="button" data-access-action="view-role" data-role-slug="${escapeHtml(role.slug)}">View permissions</button>
          ${protectedRole ? '' : `<button type="button" data-access-action="edit-role" data-role-slug="${escapeHtml(role.slug)}">Edit</button><button type="button" class="danger" data-access-action="delete-role" data-role-slug="${escapeHtml(role.slug)}">Delete</button>`}
        </div>
      </article>`;
    }).join('');
  }

  function auditRows() {
    const audit = state?.audit || [];
    if (!audit.length) return '<p class="access-muted">No access-control changes have been recorded yet.</p>';
    return `<div class="access-audit-list">${audit.map((entry) => `<div><span>${escapeHtml(entry.action.replaceAll('.', ' '))}</span><small>${escapeHtml(formatDate(entry.created_at))}</small></div>`).join('')}</div>`;
  }

  function passwordCard() {
    return `<section class="admin-panel access-password-card">
      <div class="admin-panel-head"><h2>My password</h2></div>
      <p>Change your own password here. Employee passwords are set directly by an Owner and are never shown again after saving.</p>
      <form id="access-own-password-form" class="access-inline-form">
        <label>New password<input name="password" type="password" minlength="12" autocomplete="new-password" required placeholder="At least 12 characters"></label>
        <label>Confirm password<input name="confirmPassword" type="password" minlength="12" autocomplete="new-password" required placeholder="Repeat password"></label>
        <button class="btn" type="submit">Update my password</button>
      </form>
    </section>`;
  }

  function accessMarkup() {
    const staffCount = (state?.staff || []).filter((member) => member.role !== 'customer').length;
    const activeCount = (state?.staff || []).filter((member) => member.role !== 'customer' && member.is_active && !(member.banned_until && new Date(member.banned_until).getTime() > Date.now())).length;
    return `<div class="admin-title access-title"><div><span class="eyebrow">SECURITY &amp; TEAM</span><h1>Access control</h1><p>Create roles, choose what each role can do, and manage team access without editing code.</p></div><button class="btn" type="button" data-access-action="new-role">Create role</button></div>
      <div class="admin-stats access-stats"><article><small>STAFF ACCOUNTS</small><strong>${staffCount}</strong><span>Team members with admin access</span></article><article><small>ACTIVE STAFF</small><strong>${activeCount}</strong><span>Can currently sign in</span></article><article><small>CUSTOM ROLES</small><strong>${(state?.roles || []).filter((role) => !role.is_protected).length}</strong><span>Editable permission sets</span></article><article><small>SECURITY MODEL</small><strong>Owner</strong><span>Protected full-control role</span></article></div>
      <div class="access-notice"><b>Owner safety:</b> Owners can change all staff roles and permissions. The last Owner cannot be suspended or removed. Each employee has an individual password; it is never displayed after you save it.</div>
      <div class="access-layout">
        <section class="admin-panel access-team-panel">
          <div class="admin-panel-head"><div><h2>Team members</h2><p class="access-muted">Create employee accounts, assign roles, set an individual password, or suspend sign-in access.</p></div></div>
          <form id="access-create-staff-form" class="access-invite-form">
            <label>Email address<input name="email" type="email" autocomplete="email" required placeholder="staff@example.com"></label>
            <label>Starting role<select name="role" required>${roleOptions('administrator', { includeCustomer: false })}</select></label>
            <label>Initial password<input name="password" type="password" minlength="12" maxlength="128" autocomplete="new-password" required placeholder="At least 12 characters"></label>
            <label>Confirm password<input name="confirmPassword" type="password" minlength="12" maxlength="128" autocomplete="new-password" required placeholder="Repeat password"></label>
            <button class="btn" type="submit">Create employee</button>
          </form>
          <div class="admin-table-wrap"><table class="admin-table access-team-table"><thead><tr><th>TEAM MEMBER</th><th>ROLE</th><th>STATUS</th><th>LAST SIGN-IN</th><th>SECURITY</th></tr></thead><tbody>${teamRows()}</tbody></table></div>
        </section>
        <section class="admin-panel access-role-panel"><div class="admin-panel-head"><div><h2>Roles and permissions</h2><p class="access-muted">Roles are reusable. Update a role once to update every assigned team member.</p></div></div><div class="access-role-grid">${roleCards()}</div></section>
      </div>
      <div class="access-bottom-grid">${passwordCard()}<section class="admin-panel"><div class="admin-panel-head"><h2>Recent access activity</h2></div>${auditRows()}</section></div>`;
  }

  function roleEditorMarkup(role) {
    const isNew = !role;
    const selected = new Set(role?.permissions || []);
    const groups = permissionGroups.map((group) => `<fieldset class="access-permission-group"><legend>${group.label}</legend>${group.items.map(([key, label, description]) => `<label class="access-permission"><input type="checkbox" name="permissions" value="${key}" ${selected.has(key) ? 'checked' : ''} ${key === 'admin.access' ? 'required' : ''}><span><b>${label}</b><small>${description}</small></span></label>`).join('')}</fieldset>`).join('');
    return `<div class="admin-modal-backdrop" data-access-action="close-role-editor"><section class="admin-modal access-role-modal" role="dialog" aria-modal="true" aria-labelledby="access-role-editor-title" data-access-modal><header><div><span class="eyebrow">${isNew ? 'NEW ROLE' : 'EDIT ROLE'}</span><h2 id="access-role-editor-title">${isNew ? 'Create role' : escapeHtml(role.name)}</h2></div><button class="admin-modal-close" type="button" aria-label="Close" data-access-action="close-role-editor">×</button></header><form id="access-role-form"><input type="hidden" name="slug" value="${escapeHtml(role?.slug || '')}"><div class="admin-form-grid"><label>Role name<input name="name" maxlength="80" minlength="2" required value="${escapeHtml(role?.name || '')}" placeholder="Example: Warehouse manager"></label><label>Role description<input name="description" maxlength="240" value="${escapeHtml(role?.description || '')}" placeholder="What this team member is responsible for"></label></div><p class="access-form-hint">Choose every task this role is allowed to perform. Admin panel access is required for staff roles.</p>${groups}<footer><button class="btn secondary" type="button" data-access-action="close-role-editor">Cancel</button><button class="btn" type="submit">${isNew ? 'Create role' : 'Save role'}</button></footer></form></section></div>`;
  }

  function permissionViewer(role) {
    const text = role.permissions?.includes('*') ? 'This protected Owner role has every current and future permission.' : permissionGroups.flatMap((group) => group.items).filter(([key]) => role.permissions?.includes(key)).map(([, label]) => label).join(', ') || 'No permissions selected.';
    return `<div class="admin-modal-backdrop" data-access-action="close-role-editor"><section class="admin-modal access-role-modal" role="dialog" aria-modal="true" aria-labelledby="access-role-view-title" data-access-modal><header><div><span class="eyebrow">ROLE PERMISSIONS</span><h2 id="access-role-view-title">${escapeHtml(role.name)}</h2></div><button class="admin-modal-close" type="button" aria-label="Close" data-access-action="close-role-editor">×</button></header><p class="access-role-description">${escapeHtml(role.description || 'No description added.')}</p><div class="access-readonly-permissions">${escapeHtml(text)}</div><footer><button class="btn" type="button" data-access-action="close-role-editor">Close</button></footer></section></div>`;
  }

  function passwordEditorMarkup(member) {
    return `<div class="admin-modal-backdrop" data-access-action="close-password-editor"><section class="admin-modal access-role-modal" role="dialog" aria-modal="true" aria-labelledby="access-password-editor-title" data-access-modal><header><div><span class="eyebrow">EMPLOYEE PASSWORD</span><h2 id="access-password-editor-title">Set password</h2></div><button class="admin-modal-close" type="button" aria-label="Close" data-access-action="close-password-editor">×</button></header><p class="access-role-description">Set a new individual password for <b>${escapeHtml(member.email)}</b>. It will not be displayed after saving.</p><form id="access-staff-password-form"><input type="hidden" name="userId" value="${escapeHtml(member.id)}"><div class="admin-form-grid"><label>New password<input name="password" type="password" minlength="12" maxlength="128" autocomplete="new-password" required placeholder="At least 12 characters"></label><label>Confirm password<input name="confirmPassword" type="password" minlength="12" maxlength="128" autocomplete="new-password" required placeholder="Repeat password"></label></div><footer><button class="btn secondary" type="button" data-access-action="close-password-editor">Cancel</button><button class="btn" type="submit">Save password</button></footer></form></section></div>`;
  }

  function render() {
    const workspace = document.getElementById('admin-workspace');
    if (!workspace || !state) return;
    workspace.innerHTML = accessMarkup();
    if (roleEditor) {
      workspace.insertAdjacentHTML('beforeend', roleEditor.mode === 'view' ? permissionViewer(roleEditor.role) : roleEditorMarkup(roleEditor.role));
    }
    if (passwordEditor) workspace.insertAdjacentHTML('beforeend', passwordEditorMarkup(passwordEditor));
  }

  async function request(action, payload = {}) {
    const result = await window.SAZ_SUPABASE.accessControl(action, payload);
    if (result.error) {
      notify(result.error);
      return false;
    }
    state = result.data;
    roleEditor = null;
    passwordEditor = null;
    render();
    return true;
  }

  async function openAccessControl() {
    if (!isOwner()) return notify('Only an Owner can manage staff access.');
    document.querySelectorAll('.admin-nav').forEach((item) => item.classList.remove('active'));
    document.querySelector('[data-access-tab]')?.classList.add('active');
    const workspace = document.getElementById('admin-workspace');
    if (workspace) workspace.innerHTML = '<div class="access-loading">Loading team and role controls…</div>';
    requested = true;
    await request('overview');
  }

  async function handleAction(button) {
    const action = button.dataset.accessAction;
    const slug = button.dataset.roleSlug;
    const memberId = button.dataset.memberId;
    if (action === 'close-role-editor') {
      if (button.closest('[data-access-modal]') || button.classList.contains('admin-modal-backdrop')) {
        roleEditor = null;
        render();
      }
      return;
    }
    if (action === 'close-password-editor') {
      if (button.closest('[data-access-modal]') || button.classList.contains('admin-modal-backdrop')) {
        passwordEditor = null;
        render();
      }
      return;
    }
    if (action === 'new-role') {
      roleEditor = { mode: 'edit', role: null };
      render();
      return;
    }
    if (action === 'edit-role') {
      roleEditor = { mode: 'edit', role: roleBySlug(slug) };
      render();
      return;
    }
    if (action === 'view-role') {
      roleEditor = { mode: 'view', role: roleBySlug(slug) };
      render();
      return;
    }
    if (action === 'delete-role') {
      const role = roleBySlug(slug);
      if (role && window.confirm(`Delete the ${role.name} role? This only works when no team member uses it.`)) await request('delete_role', { slug });
      return;
    }
    const member = state?.staff?.find((item) => item.id === memberId);
    if (action === 'set-password' && member) {
      passwordEditor = member;
      render();
      return;
    }
    if (action === 'toggle-status' && member) {
      const active = button.dataset.active === 'true';
      const verb = active ? 'restore access for' : 'suspend';
      if (window.confirm(`Do you want to ${verb} ${member.email}?`)) await request('set_status', { userId: memberId, active });
    }
  }

  function installListeners() {
    // Capture this before the legacy admin handlers can open an editor or
    // switch to a forbidden workspace. Database rules remain the authority.
    document.addEventListener('click', (event) => {
      const tab = event.target.closest?.('[data-action="admin-tab"][data-view]');
      const tabPermission = tab && viewPermissions[tab.dataset.view];
      const action = event.target.closest?.('[data-action]');
      const actionPermission = action && actionPermissions[action.dataset.action];
      if ((tabPermission && !can(tabPermission)) || (actionPermission && !can(actionPermission))) {
        event.preventDefault();
        event.stopImmediatePropagation();
        notify('Your role does not have permission for that action.');
      }
    }, true);

    document.addEventListener('click', (event) => {
      const accessTab = event.target.closest?.('[data-access-tab]');
      if (accessTab) {
        event.preventDefault();
        openAccessControl();
        return;
      }
      const action = event.target.closest?.('[data-access-action]');
      if (!action) return;
      if (action.classList.contains('admin-modal-backdrop') && event.target !== action) return;
      event.preventDefault();
      handleAction(action);
    });

    document.addEventListener('change', (event) => {
      const select = event.target.closest?.('.access-role-select');
      if (!select) return;
      const member = state?.staff?.find((item) => item.id === select.dataset.memberId);
      if (!member) return;
      const nextRole = select.value;
      if (window.confirm(`Change ${member.email} to ${labelForRole(nextRole)}?`)) request('assign_role', { userId: member.id, role: nextRole });
      else select.value = member.role;
    });

    document.addEventListener('submit', async (event) => {
      const form = event.target;
      if (!(form instanceof HTMLFormElement)) return;
      if (form.id === 'access-create-staff-form') {
        event.preventDefault();
        const values = new FormData(form);
        const password = String(values.get('password') || '');
        if (password.length < 12) return notify('Use a password with at least 12 characters.');
        if (password !== values.get('confirmPassword')) return notify('The passwords do not match.');
        if (await request('create_staff', { email: values.get('email'), role: values.get('role'), password })) notify('Employee account created. Give the password privately.');
      }
      if (form.id === 'access-role-form') {
        event.preventDefault();
        const values = new FormData(form);
        await request('save_role', {
          slug: values.get('slug'),
          name: values.get('name'),
          description: values.get('description'),
          permissions: values.getAll('permissions')
        });
      }
      if (form.id === 'access-own-password-form') {
        event.preventDefault();
        const values = new FormData(form);
        const password = String(values.get('password') || '');
        if (password.length < 12) return notify('Use a password with at least 12 characters.');
        if (password !== values.get('confirmPassword')) return notify('The passwords do not match.');
        const { error } = await window.SAZ_SUPABASE.updateOwnPassword(password);
        if (error) return notify(error.message || 'Could not update your password.');
        form.reset();
        notify('Your password was updated.');
      }
      if (form.id === 'access-staff-password-form') {
        event.preventDefault();
        const values = new FormData(form);
        const password = String(values.get('password') || '');
        if (password.length < 12) return notify('Use a password with at least 12 characters.');
        if (password !== values.get('confirmPassword')) return notify('The passwords do not match.');
        if (await request('set_staff_password', { userId: values.get('userId'), password })) notify('Employee password changed. Give the new password privately.');
      }
    }, true);
  }

  function enhance() {
    if (location.pathname.split('/').pop() !== 'admin.html' || !window.SAZ_SUPABASE?.isAdmin?.()) return;
    addNav();
    applyNavigationPermissions();
    if (!booted) {
      booted = true;
      installListeners();
    }
  }

  new MutationObserver(enhance).observe(document.documentElement, { childList: true, subtree: true });
  document.addEventListener('DOMContentLoaded', enhance);
  setTimeout(enhance, 0);
})();
