(() => {
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

  if (
    !config?.url ||
    !config?.publishableKey ||
    !window.supabase?.createClient
  ) {
    console.warn('Supabase configuration is missing.');
    return;
  }

  const client = window.supabase.createClient(
    config.url,
    config.publishableKey
  );

  let admin = false;
  let hydrated = false;

  const parse = (value) => {
    try {
      return JSON.parse(value);
    } catch {
      return null;
    }
  };

  const writeLocal = (key, value) => {
    localStorage.setItem(key, JSON.stringify(value));
  };

  async function refreshRole() {
    const {
      data: { user }
    } = await client.auth.getUser();

    if (!user) {
      admin = false;
      return false;
    }

    const { data, error } = await client
      .from('profiles')
      .select('role')
      .eq('id', user.id)
      .maybeSingle();

    if (error) {
      console.error('Could not check admin role:', error.message);
      admin = false;
      return false;
    }

    admin = data?.role === 'admin';
    return admin;
  }

  async function hydrate() {
    if (hydrated) return;

    const { data, error } = await client
      .from('store_state')
      .select('key,value');

    if (error) {
      console.warn(
        'Supabase storefront data is not ready yet:',
        error.message
      );
      return;
    }

    for (const row of data || []) {
      const key = Object.keys(stateNames).find(
        (k) => stateNames[k] === row.key
      );

      if (key) {
        writeLocal(key, row.value);
      }
    }

    hydrated = true;
  }

  async function syncState(key, value) {
    if (!sharedKeys.has(key) || !admin) return;

    const { error } = await client
      .from('store_state')
      .upsert({
        key: stateNames[key],
        value,
        updated_at: new Date().toISOString()
      });

    if (error) {
      console.error(
        'Could not save store data:',
        error.message
      );
    }
  }

  async function syncOrders(orders) {
    if (!Array.isArray(orders) || !orders.length) return;

    const asRow = (order) => ({
      reference: order.ref,
      customer_name: order.customer || null,
      phone: order.phone || null,
      email: order.email || null,
      address: order.address || null,
      city: order.city || null,
      district: order.district || null,
      division: order.division || null,
      payment_method: order.payment || null,
      subtotal: Number(order.subtotal || 0),
      shipping: Number(order.shipping || 0),
      discount: Number(order.discount || 0),
      total: Number(order.total || 0),
      coupon: order.coupon || null,
      status: order.status || 'Processing',
      line_items: order.lines || [],
      created_at:
        order.createdAt || new Date().toISOString()
    });

    const rows = (admin ? orders : orders.slice(0, 1))
      .filter((order) => order?.ref)
      .map(asRow);

    if (!rows.length) return;

    const request = admin
      ? client
          .from('orders')
          .upsert(rows, { onConflict: 'reference' })
      : client
          .from('orders')
          .insert(rows[0]);

    const { error } = await request;

    if (error) {
      console.error(
        'Could not save order:',
        error.message
      );
    }
  }

  async function syncMessages(messages) {
    if (!Array.isArray(messages) || !messages.length) return;

    const message = messages[0];

    if (!message?.id) return;

    const { error } = await client
      .from('contact_messages')
      .upsert(
        {
          id: message.id,
          name: message.name,
          email: message.email,
          subject: message.subject,
          message: message.message,
          created_at:
            message.date || new Date().toISOString()
        },
        {
          onConflict: 'id',
          ignoreDuplicates: true
        }
      );

    if (error) {
      console.error(
        'Could not save contact message:',
        error.message
      );
    }
  }

  window.SAZ_SUPABASE = {
    client,
    hydrate,
    refreshRole,

    isAdmin: () => admin,

    async signIn(email, password) {
      const result = await client.auth.signInWithPassword({
        email,
        password
      });

      if (!result.error) {
        await refreshRole();
      }

      return result;
    },

    async signOut() {
      admin = false;
      return client.auth.signOut();
    },

    sync(key, value) {
      if (key === 'sazOrders') {
        return syncOrders(value);
      }

      if (key === 'sazMessages') {
        return syncMessages(value);
      }

      return syncState(key, value);
    }
  };
})();