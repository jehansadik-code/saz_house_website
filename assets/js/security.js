/* Launch hardening layer. Loaded before app.js so it owns sensitive submits. */
(() => {
  'use strict';

  const MAX_IMAGE_BYTES = 5 * 1024 * 1024;
  const SAFE_IMAGE_TYPES = new Set(['image/jpeg', 'image/png', 'image/webp']);
  const safeText = value => String(value ?? '').replace(/[<>]/g, '').trim();
  const safeUrl = (value, { image = false } = {}) => {
    const raw = String(value ?? '').trim();
    if (!raw) return '';
    if (image && raw.startsWith('data:image/')) return raw;
    try {
      const url = new URL(raw, window.location.origin);
      if (!['https:', 'http:'].includes(url.protocol)) return '';
      return raw;
    } catch {
      return raw.startsWith('assets/images/catalog/') || raw.startsWith('logo.') || raw.startsWith('videos/') ? raw : '';
    }
  };
  const notify = message => window.toast ? window.toast(message) : window.alert(message);
  const installHoneypot = root => {
    for (const form of root.querySelectorAll?.('#checkout-form, #contact-form') || []) {
      if (form.elements.website) continue;
      const field = document.createElement('input');
      field.name = 'website'; field.type = 'text'; field.tabIndex = -1;
      field.autocomplete = 'off'; field.setAttribute('aria-hidden', 'true');
      field.style.cssText = 'position:absolute;left:-10000px;width:1px;height:1px;overflow:hidden';
      form.append(field);
    }
  };

  new MutationObserver(records => records.forEach(record => record.addedNodes.forEach(node => {
    if (node.nodeType === Node.ELEMENT_NODE) {
      installHoneypot(node);
      node.querySelectorAll?.('.facebook-qr img').forEach(image => {
        image.src = 'assets/images/social/facebook-qr.png';
      });
    }
  }))).observe(document.documentElement, { childList: true, subtree: true });

  document.addEventListener('change', event => {
    const input = event.target;
    if (!(input instanceof HTMLInputElement) || input.type !== 'file') return;
    for (const file of input.files || []) {
      if (!SAFE_IMAGE_TYPES.has(file.type) || file.size > MAX_IMAGE_BYTES) {
        input.value = '';
        notify('Use a JPG, PNG, or WebP image smaller than 5 MB.');
        event.stopImmediatePropagation();
        return;
      }
    }
  }, true);

  document.addEventListener('click', event => {
    const link = event.target.closest?.('a[href]');
    if (link && !safeUrl(link.getAttribute('href'))) {
      event.preventDefault();
      notify('Blocked an unsafe link.');
    }
  }, true);

  document.addEventListener('error', event => {
    const image = event.target;
    if (!(image instanceof HTMLImageElement) || image.dataset.fallbackApplied) return;
    image.dataset.fallbackApplied = 'true';
    image.src = 'assets/images/brand/logo.png';
    image.alt = image.alt || 'SAZ House';
  }, true);

  document.addEventListener('submit', async event => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;

    if (form.id === 'admin-login-form') {
      event.preventDefault();
      event.stopImmediatePropagation();
      if (!window.SAZ_SUPABASE) return notify('Secure sign-in is temporarily unavailable.');
      const data = new FormData(form);
      const result = await window.SAZ_SUPABASE.signIn(data.get('email'), data.get('password'));
      if (result.error || !window.SAZ_SUPABASE.isAdmin()) {
        await window.SAZ_SUPABASE.signOut();
        return notify('Invalid administrator credentials.');
      }
      localStorage.setItem('sazAdmin', 'true');
      location.reload();
      return;
    }

    if (form.id === 'login-form') {
      event.preventDefault();
      event.stopImmediatePropagation();
      if (!window.SAZ_SUPABASE) return notify('Secure sign-in is temporarily unavailable.');
      const data = new FormData(form);
      const result = await window.SAZ_SUPABASE.signIn(data.get('email'), data.get('password'));
      if (result.error) return notify('Email or password is incorrect.');
      localStorage.setItem('sazUser', JSON.stringify({ email: safeText(data.get('email')) }));
      location.reload();
      return;
    }

    if (form.id === 'checkout-form' || form.id === 'contact-form') {
      event.preventDefault();
      event.stopImmediatePropagation();
      const data = new FormData(form);
      const action = form.id === 'checkout-form' ? 'checkout' : 'contact';
      const payload = action === 'checkout'
        ? {
            action,
            cart: JSON.parse(localStorage.getItem('sazCart') || '[]'),
            customer: Object.fromEntries(['name', 'phone', 'email', 'address', 'district', 'division'].map(key => [key, safeText(data.get(key))])),
            deliveryArea: safeText(data.get('deliveryArea') || data.get('city')),
            payment: safeText(data.get('payment')),
            coupon: safeText(localStorage.getItem('sazCouponCode')),
            website: safeText(data.get('website'))
          }
        : {
            action,
            name: safeText(data.get('name')),
            email: safeText(data.get('email')),
            subject: safeText(data.get('subject')),
            message: safeText(data.get('message')),
            website: safeText(data.get('website'))
          };
      try {
        const response = await fetch(`${window.SAZ_SUPABASE_CONFIG.url}/functions/v1/storefront`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            apikey: window.SAZ_SUPABASE_CONFIG.publishableKey
          },
          body: JSON.stringify(payload)
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || 'Request could not be completed.');
        if (action === 'contact') {
          form.reset();
          document.getElementById('contact-notice')?.style && (document.getElementById('contact-notice').style.display = 'block');
          return;
        }
        localStorage.setItem('sazLastOrder', JSON.stringify(result.order));
        localStorage.removeItem('sazCart');
        localStorage.removeItem('sazCouponCode');
        location.href = 'success.html';
      } catch (error) {
        notify(error.message || 'Could not submit your request. Please try again.');
      }
    }
  }, true);

  // Normalize old browser data before legacy templates render it.
  for (const key of ['sazUser', 'sazMessages']) {
    try {
      const value = JSON.parse(localStorage.getItem(key));
      if (key === 'sazUser' && value?.email) localStorage.setItem(key, JSON.stringify({ email: safeText(value.email) }));
      if (key === 'sazMessages' && Array.isArray(value)) {
        localStorage.setItem(key, JSON.stringify(value.map(message => Object.fromEntries(
          Object.entries(message).map(([name, text]) => [name, typeof text === 'string' ? safeText(text) : text])
        ))));
      }
    } catch { localStorage.removeItem(key); }
  }
})();
