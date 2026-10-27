# SAZ House

Static HTML, CSS, and JavaScript storefront backed by Supabase Auth, database RPCs, and Edge Functions. Vercel serves the static files. The cart and wishlist are browser caches; orders, stock, products, coupons, settings, and contact messages belong to Supabase.

## Local development

1. Check that `assets/js/supabase-config.js` contains the intended Supabase project URL and **publishable** key. Never place a service-role or secret key in a browser file.
2. Serve the repository from an allowed origin, for example `py -m http.server 5500`, then open `http://localhost:5500`. Opening `index.html` through `file://` does not provide an allowed origin for the public Edge Function.
3. Set `ALLOWED_ORIGINS` for the Supabase functions to include the exact local origin while developing. Production must include the exact Vercel or custom-domain origin.
4. Run `node --test tests/backend-contract.test.mjs` for the local contract checks.

## Features and limits

- Product catalog, filters, cart, wishlist, checkout, contact form, and staff dashboard.
- Checkout and contact forms call the `storefront` Edge Function. It uses a server-side service-role client; checkout totals and stock are computed in a database transaction.
- Staff use Supabase Auth and role permissions. The Owner manages staff through `manage-access`.
- Enabled payment choices come from store settings. `Card (demo)` does not charge a card. Do not enable it for real payments.
- Customer order history is not connected to accounts. The order reference on the confirmation page is the current way to identify an order.
- Images are currently stored in large `store_state` JSON values; migrate uploads to storage before growing the catalog.

See [LAUNCH.md](LAUNCH.md) for the database migration order, secrets, deployment steps, and release checks. Do not run the fresh-project schema on an existing store.
