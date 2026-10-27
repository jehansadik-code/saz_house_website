(() => {
  'use strict';

  const config = window.SAZ_SUPABASE_CONFIG;
  const sharedKeys = new Set([
    'sazProducts',
    'sazProductTypes',
    'sazCoupons',
    'sazSettings',
    'sazSiteContent',
    'sazPageProducts',
    'sazHomeCategories'
  ]);
  const stateNames = {
    sazProducts: 'products',
    sazProductTypes: 'product_types',
    sazCoupons: 'coupons',
    sazSettings: 'settings',
    sazSiteContent: 'site_content',
    sazPageProducts: 'page_products',
    sazHomeCategories: 'home_categories'
  };
  const statePermissions = {
    sazProducts: 'products.manage',
    sazProductTypes: 'products.manage',
    sazCoupons: 'coupons.manage',
    sazSettings: 'settings.manage',
    sazSiteContent: 'content.manage',
    sazPageProducts: 'content.manage',
    sazHomeCategories: 'content.manage'
  };
  const protectedCaches = {
    sazOrders: 'orders.view',
    sazMessages: 'messages.view'
  };

  if (!config?.url || !config?.publishableKey || !window.supabase?.createClient) {
    console.warn('Supabase configuration is missing.');
    return;
  }

  const client = window.supabase.createClient(config.url, config.publishableKey);
  let admin = false;
  let currentUser = null;
  let hydrated = false;
  let currentRole = null;
  let permissions = new Set();

  const writeLocal = (key, value) => localStorage.setItem(key, JSON.stringify(value));
  const allowed = (permission) => permissions.has('*') || permissions.has(permission);
  const clearUnauthorizedCaches = () => Object.entries(protectedCaches).forEach(([key, permission]) => {
    if (!allowed(permission)) localStorage.removeItem(key);
  });

  async function refreshRole() {
    const { data: { user } } = await client.auth.getUser();
    currentUser = user || null;
    if (!user) {
      admin = false;
      currentRole = null;
      permissions = new Set();
      clearUnauthorizedCaches();
      return false;
    }

    const { data: profile, error: profileError } = await client
      .from('profiles')
      .select('role,is_active')
      .eq('id', user.id)
      .maybeSingle();

    if (profileError || !profile?.role || !profile.is_active) {
      console.error('Could not check access role:', profileError?.message || 'No role assigned.');
      admin = false;
      currentRole = null;
      permissions = new Set();
      clearUnauthorizedCaches();
      return false;
    }

    const { data: role, error: roleError } = await client
      .from('access_roles')
      .select('slug,name,permissions,is_protected')
      .eq('slug', profile.role)
      .maybeSingle();

    if (roleError || !role) {
      console.error('Could not load role permissions:', roleError?.message || 'Role not found.');
      admin = false;
      currentRole = null;
      permissions = new Set();
      clearUnauthorizedCaches();
      return false;
    }

    currentRole = role;
    permissions = new Set(Array.isArray(role.permissions) ? role.permissions : []);
    admin = allowed('admin.access');
    clearUnauthorizedCaches();
    return admin;
  }

  async function hydrate({ force = false } = {}) {
    if (hydrated && !force) return;
    const { data, error } = await client.from('store_state').select('key,value');
    if (error) {
      console.warn('Supabase storefront data is not ready yet:', error.message);
      return;
    }
    for (const row of data || []) {
      const key = Object.keys(stateNames).find((item) => stateNames[item] === row.key);
      if (key) writeLocal(key, row.value);
    }

    if (allowed('orders.view')) {
      const { data: orders, error: ordersError } = await client.rpc('list_staff_orders');
      if (ordersError) {
        console.warn('Could not load orders for this role:', ordersError.message);
      } else {
        writeLocal('sazOrders', (orders || []).map((order) => ({
          ref: order.reference,
          date: new Date(order.created_at).toLocaleDateString(),
          createdAt: order.created_at,
          lines: order.line_items || [],
          items: Array.isArray(order.line_items) ? order.line_items.length : 0,
          subtotal: Number(order.subtotal || 0),
          shipping: Number(order.shipping || 0),
          discount: Number(order.discount || 0),
          total: Number(order.total || 0),
          coupon: order.coupon || '',
          status: order.status,
          customer: order.customer_name || '',
          phone: order.phone || '',
          email: order.email || '',
          address: order.address || '',
          city: order.city || '',
          district: order.district || '',
          division: order.division || '',
          payment: order.payment_method || ''
        })));
      }
    }

    if (allowed('messages.view')) {
      const { data: messages, error: messagesError } = await client
        .from('contact_messages')
        .select('id,name,email,subject,message,created_at')
        .order('created_at', { ascending: false })
        .limit(500);
      if (messagesError) {
        console.warn('Could not load messages for this role:', messagesError.message);
      } else {
        writeLocal('sazMessages', (messages || []).map((message) => ({
          id: message.id,
          name: message.name,
          email: message.email,
          subject: message.subject || '',
          message: message.message,
          date: message.created_at
        })));
      }
    }
    hydrated = true;
  }

  async function syncState(key, value) {
    if (!sharedKeys.has(key) || (!allowed('store.manage') && !allowed(statePermissions[key]))) {
      return { ok: true, skipped: true };
    }
    const { error } = await client.from('store_state').upsert({
      key: stateNames[key],
      value,
      updated_at: new Date().toISOString()
    });
    if (error) {
      console.error('Could not save store data:', error.message);
      return { ok: false, error: error.message };
    }
    return { ok: true };
  }

  async function syncOrders(orders) {
    // The dashboard can only synchronize fulfillment status. Checkout fields,
    // totals and line items always remain the server's source of truth.
    if (!allowed('orders.manage') || !Array.isArray(orders) || !orders.length) {
      return { ok: true, skipped: true };
    }
    const validStatuses = new Set(['Processing', 'Shipped', 'Delivered', 'Cancelled']);
    const updates = [...new Map(orders
      .filter((order) => order?.ref && validStatuses.has(order.status))
      .map((order) => [order.ref, order.status])).entries()];
    const results = await Promise.all(updates.map(async ([reference, status]) => {
      const { error } = await client.rpc('update_staff_order_status', { p_reference: reference, p_status: status });
      return error?.message || null;
    }));
    const failure = results.find(Boolean);
    if (failure) {
      console.error('Could not update order status:', failure);
      return { ok: false, error: failure };
    }
    return { ok: true };
  }

  async function syncMessages(messages) {
    // Contact submissions are handled by the hardened Edge Function.
    if (!Array.isArray(messages) || !messages.length) return { ok: true, skipped: true };
    return { ok: true, skipped: true };
  }

  async function accessControl(action, payload = {}) {
    const { data, error } = await client.functions.invoke('manage-access', {
      body: { action, ...payload }
    });
    if (error) {
      let message = error.message || 'Access-control request failed.';
      const functionUnavailable = /failed to send a request to the edge function/i.test(message)
        || error.context?.status === 404;
      if (functionUnavailable) {
        message = 'Access Control is not connected yet. Deploy the manage-access Edge Function, then refresh this page.';
      }
      try {
        const response = await error.context?.json();
        if (!functionUnavailable) message = response?.error || response?.message || message;
      } catch (_) {
        // The function already returned the most useful available error.
      }
      return { data: null, error: message };
    }
    if (data?.error) return { data: null, error: data.error };
    return { data: data?.data ?? null, error: null };
  }

  window.SAZ_SUPABASE = {
    client,
    hydrate,
    refreshRole,
    isAdmin: () => admin,
    hasPermission: (permission) => allowed(permission),
    getRole: () => currentRole ? { ...currentRole, permissions: [...permissions] } : null,
    getUser: () => currentUser ? { id: currentUser.id, email: currentUser.email || '' } : null,
    accessControl,
    async signIn(email, password) {
      const result = await client.auth.signInWithPassword({ email, password });
      if (!result.error) await refreshRole();
      return result;
    },
    async signOut() {
      admin = false;
      currentUser = null;
      currentRole = null;
      permissions = new Set();
      return client.auth.signOut();
    },
    async updateOwnPassword(password) {
      return client.auth.updateUser({ password });
    },
    sync(key, value) {
      if (key === 'sazOrders') return syncOrders(value);
      if (key === 'sazMessages') return syncMessages(value);
      return syncState(key, value);
    }
  };
})();
