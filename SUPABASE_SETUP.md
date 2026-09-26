# Supabase setup

The website uses the public URL and publishable key in `supabase-config.js`. The secret key is intentionally not used or stored in this repository.

1. In the Supabase SQL Editor, run [`supabase/schema.sql`](supabase/schema.sql).
2. In **Authentication > Providers**, enable Email. For a live shop, configure your Vercel production URL and preview URL in **Authentication > URL Configuration**.
3. Create your owner account in Supabase Authentication, then run the final `update public.profiles ...` statement from the schema with your email address. This is what authorizes the admin panel to change catalog and settings data.
4. Sign in to the admin page with that Supabase account. The existing catalog will then be saved to `store_state`; customer orders and messages are saved as they are submitted.
5. Deploy the changed files to Vercel. No Vercel secret is required for this static implementation.

Security: rotate the secret key shared in chat before using the project in production. Browser code must contain only the publishable key.
