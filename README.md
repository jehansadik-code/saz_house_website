# SAZ House storefront

A responsive, self-contained storefront built with HTML, CSS and vanilla JavaScript. Open `index.html` in a browser (or serve this directory with a local static server). Cart contents, favorites, and the demo customer profile are stored in browser local storage.

## Pages

- `index.html` home
- `shop.html` catalog, category and price filters, sorting and search
- `product.html` product detail, color/size selection and add to cart
- `cart.html` cart quantity/removal and order totals
- `checkout.html` shipping, payment selection, form validation and demo order confirmation
- `account.html` local demo account, order history and wishlist
- `about.html`, `contact.html`, `faq.html`
- `admin.html` local admin panel for products, stock, coupons, delivery, payment settings, orders, messages, store statistics, site content, and JSON backup/restore

Admin demo login: `admin@sazhouse.com` / `Admin123`. Open `admin.html` to sign in. Product images can be entered one per line or uploaded in batches; product pages show them in a clickable gallery. Videos use a direct web/local `.mp4` path. Product types can be added or removed from the product editor, and the “Other” option accepts a custom type. Products support description, size list, stock, visibility, price, sale price and badge. Coupons support percentage/fixed discounts and minimum spend. Settings control inside/outside Dhaka delivery costs, free-delivery threshold, and whether COD, bKash, Nagad or demo card options appear at checkout. The Site Content editor updates homepage copy, announcement, about story, contact details, footer text, and logo path. Admin tools can download and restore a JSON backup. The admin panel and storefront share this browser's local storage, so records do not sync to other devices and can be cleared with browser data. The demo login is not secure for a live store; production admin access, shared data, and real payment processing require a backend.

## Project organization

See [DIAGNOSTIC.md](DIAGNOSTIC.md) for the current folder map, checks, and findings. Runtime product images and homepage slides are under `images/`; the shared brand logo is `logo.png`.
