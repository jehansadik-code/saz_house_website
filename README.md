# SAZ House

<p align="center">
  <img src="assets/images/brand/logo.png" alt="SAZ House Logo" width="180">
</p>

<p align="center">
  A responsive e-commerce storefront built with HTML, CSS and vanilla JavaScript.
</p>

## Features

* 🛍️ Product catalog and categories
* 🔎 Search, filtering and sorting
* 🛒 Shopping cart and checkout
* ❤️ Wishlist and favorites
* 👤 Customer account and order history
* 🎟️ Coupon and discount system
* 📦 Stock and product management
* ⚙️ Local admin dashboard
* 💳 COD, bKash, Nagad and demo card options
* 💾 LocalStorage-based data and JSON backup/restore
* 📱 Responsive design

## Pages

`Home` · `Shop` · `Product` · `Cart` · `Checkout` · `Account` · `About` · `Contact` · `FAQ` · `Admin`

## Tech Stack

* HTML5
* CSS3
* JavaScript
* Browser LocalStorage

## Run Locally

Simply open:

```text
index.html
```

in your browser, or use a local static server.

## Admin access

Administration uses Supabase Auth with role-based permissions. The protected `Owner` role can directly create or suspend employee accounts, set an employee's individual password, create custom roles, and select the exact permissions for each role from the admin panel. No invitation or reset email is sent. Passwords are stored by Supabase Auth and are never displayed after saving. Follow [LAUNCH.md](LAUNCH.md) before deploying.

## Note

The cart can be stored locally for convenience. Production orders, inventory, coupons, messages and administrator permissions must be enforced by Supabase using the included schema, hardening migration and Edge Function.

---

**SAZ House — E-commerce Storefront**
