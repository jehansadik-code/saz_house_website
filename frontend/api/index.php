<?php
declare(strict_types=1);

require __DIR__ . '/../../backend/lib.php';

try {
    $route = trim((string) ($_GET['route'] ?? ''), '/');
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    if ($method === 'OPTIONS') { http_response_code(204); exit; }

    match ([$method, $route]) {
        ['GET', 'csrf'] => out(['csrf' => csrf(), 'user' => user_summary(current_user())]),
        ['GET', 'storefront'] => storefront_read(),
        ['POST', 'auth/login'] => login(),
        ['POST', 'auth/logout'] => logout(),
        ['POST', 'auth/password'] => password_change(),
        ['POST', 'auth/password-reset/request'] => password_reset_request(),
        ['POST', 'auth/password-reset/confirm'] => password_reset_confirm(),
        ['POST', 'checkout'] => checkout(),
        ['POST', 'contact'] => contact(),
        ['POST', 'admin/state'] => state_save(),
        ['GET', 'admin/orders'] => orders_read(),
        ['POST', 'admin/orders/status'] => order_status(),
        ['GET', 'admin/messages'] => messages_read(),
        ['POST', 'admin/access'] => access(),
        ['POST', 'admin/upload'] => upload_image(),
        default => fail('Not found.', 404),
    };
} catch (Throwable $error) {
    error_log(sprintf('SAZ API error: %s', $error->getMessage()));
    [$message, $status] = safe_error($error);
    fail($message, $status);
}

function storefront_read(): never {
    $rows = db()->query('SELECT `key`,value,revision FROM store_state')->fetchAll();
    $state = [];
    $versions = [];
    foreach ($rows as $row) {
        $state[$row['key']] = json_decode((string) $row['value'], true);
        $versions[$row['key']] = (int) $row['revision'];
    }
    out(['state' => $state, 'versions' => $versions, 'csrf' => csrf(), 'user' => user_summary(current_user())]);
}

function fingerprint(string $action, string $identity): string {
    return hash('sha256', $action . '|' . $identity . '|' . cfg()['throttle_pepper']);
}

function submission_slot(string $action, string $identity, int $seconds): void {
    $now = gmdate('Y-m-d H:i:s');
    $cutoff = gmdate('Y-m-d H:i:s', time() - $seconds);
    $query = db()->prepare('INSERT INTO submission_throttle(fingerprint,action,last_seen) VALUES(?,?,?) ON DUPLICATE KEY UPDATE last_seen=IF(last_seen<=?,VALUES(last_seen),last_seen)');
    $query->execute([fingerprint($action, $identity), $action, $now, $cutoff]);
    if ($query->rowCount() === 0) { header('Retry-After: ' . $seconds); fail('Please wait a moment before trying again.', 429); }
}

function login(): never {
    require_csrf();
    $input = request_body();
    $address = filter_var($_SERVER['REMOTE_ADDR'] ?? '', FILTER_VALIDATE_IP) ?: 'unknown';
    $mail = email($input['email'] ?? null);
    $password = $input['password'] ?? null;
    if (!$mail || !is_string($password)) fail('Email or password is incorrect.', 401);
    submission_slot('login', $address . '|' . $mail, 3);
    $query = db()->prepare('SELECT id,password_hash,is_active FROM users WHERE email=?');
    $query->execute([$mail]);
    $record = $query->fetch();
    if (!$record || !(bool) $record['is_active'] || !password_verify($password, $record['password_hash'])) fail('Email or password is incorrect.', 401);
    session_start_secure();
    session_regenerate_id(true);
    $_SESSION['uid'] = $record['id'];
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
    db()->prepare('UPDATE users SET last_sign_in_at=UTC_TIMESTAMP() WHERE id=?')->execute([$record['id']]);
    out(['ok' => true, 'csrf' => csrf(), 'user' => user_summary(current_user())]);
}

function logout(): never {
    require_csrf();
    session_start_secure();
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 3600, $params['path'], '', (bool) $params['secure'], (bool) $params['httponly']);
    }
    session_destroy();
    out(['ok' => true]);
}

function password_change(): never {
    $user = require_permission('admin.access');
    require_csrf();
    $password = strong_password(request_body()['password'] ?? null);
    db()->prepare('UPDATE users SET password_hash=? WHERE id=?')->execute([password_hash($password, PASSWORD_DEFAULT), $user['id']]);
    audit($user['id'], 'staff.password_changed', 'user', $user['id']);
    out(['ok' => true]);
}

function password_reset_request(): never {
    require_csrf();
    $mail = email(request_body()['email'] ?? null);
    // Do not reveal whether an account exists. Invalid input gets the same
    // response so this endpoint cannot be used to enumerate staff accounts.
    if (!$mail) out(['ok' => true, 'message' => 'If an account exists, a reset link has been sent.']);
    submission_slot('password-reset', $mail, 60);
    $record = db()->prepare('SELECT id,email FROM users WHERE email=? AND is_active=1');
    $record->execute([$mail]);
    $user = $record->fetch();
    if ($user) {
        $selector = bin2hex(random_bytes(16));
        $token = bin2hex(random_bytes(32));
        $minutes = min(120, max(5, (int) (cfg()['password_reset_ttl_minutes'] ?? 30)));
        transaction(function (PDO $pdo) use ($user, $selector, $token, $minutes): void {
            $expires = gmdate('Y-m-d H:i:s', time() + ($minutes * 60));
            $update = $pdo->prepare('UPDATE users SET password_reset_selector=?, password_reset_token_hash=?, password_reset_expires_at=? WHERE id=?');
            $update->execute([$selector, hash('sha256', $token), $expires, $user['id']]);
            audit(null, 'auth.password_reset_requested', 'user', $user['id']);
        });
        if (!send_password_reset_email((string) $user['email'], $selector, $token)) {
            error_log('SAZ password-reset email delivery failed for user id ' . $user['id']);
        }
    }
    out(['ok' => true, 'message' => 'If an account exists, a reset link has been sent.']);
}

function password_reset_confirm(): never {
    require_csrf();
    $input = request_body();
    $selector = text($input['selector'] ?? '', 32);
    $token = text($input['token'] ?? '', 64);
    if (!preg_match('/^[a-f0-9]{32}$/', $selector) || !preg_match('/^[a-f0-9]{64}$/', $token)) fail('Invalid or expired password-reset link.', 400);
    $password = strong_password($input['password'] ?? null);
    $changed = transaction(function (PDO $pdo) use ($selector, $token, $password): bool {
        $query = $pdo->prepare('SELECT id,password_reset_token_hash,password_reset_expires_at FROM users WHERE password_reset_selector=? AND is_active=1 FOR UPDATE');
        $query->execute([$selector]);
        $user = $query->fetch();
        if (!$user || !is_string($user['password_reset_token_hash']) || !is_string($user['password_reset_expires_at'])
            || strtotime($user['password_reset_expires_at'] . ' UTC') < time()
            || !hash_equals($user['password_reset_token_hash'], hash('sha256', $token))) return false;
        $update = $pdo->prepare('UPDATE users SET password_hash=?, password_reset_selector=NULL, password_reset_token_hash=NULL, password_reset_expires_at=NULL WHERE id=?');
        $update->execute([password_hash($password, PASSWORD_DEFAULT), $user['id']]);
        audit(null, 'auth.password_reset_completed', 'user', $user['id']);
        return true;
    });
    if (!$changed) fail('Invalid or expired password-reset link.', 400);
    out(['ok' => true]);
}

function contact(): never {
    $input = request_body();
    if (text($input['website'] ?? '', 200) !== '') out(['ok' => true]);
    require_csrf();
    $name = text($input['name'] ?? '', 100);
    $mail = email($input['email'] ?? null);
    $message = text($input['message'] ?? '', 4000);
    if (!$name || !$mail || !$message) fail('Enter your name, a valid email address, and a message.');
    submission_slot('contact', $mail, 30);
    $query = db()->prepare('INSERT INTO contact_messages(id,name,email,subject,message) VALUES(?,?,?,?,?)');
    $query->execute([uuid(), $name, $mail, text($input['subject'] ?? '', 160) ?: null, $message]);
    out(['ok' => true], 201);
}

function checkout(): never {
    $input = request_body();
    if (text($input['website'] ?? '', 200) !== '') out(['ok' => true]);
    require_csrf();
    $customer = is_array($input['customer'] ?? null) ? $input['customer'] : [];
    $name = text($customer['name'] ?? '', 100);
    $phone = text($customer['phone'] ?? '', 30);
    $mail = email($customer['email'] ?? null);
    $address = text($customer['address'] ?? '', 500);
    $idempotency = text($input['idempotencyKey'] ?? ($_SERVER['HTTP_IDEMPOTENCY_KEY'] ?? ''), 128);
    $cart = $input['cart'] ?? null;
    $payment = text($input['payment'] ?? '', 30);
    $area = text($input['deliveryArea'] ?? '', 30);
    $couponCode = text($input['coupon'] ?? '', 50);
    if (!$name || !preg_match('/^[0-9+() -]{7,30}$/', $phone) || (!$mail && text($customer['email'] ?? '', 254)) || strlen($address) < 5 || !preg_match('/^[A-Za-z0-9_-]{16,128}$/', $idempotency) || !is_array($cart) || count($cart) < 1 || count($cart) > 25) fail('Please check your checkout details and try again.');
    if (!in_array($payment, ['Cash on Delivery', 'bKash', 'Nagad', 'Card (demo)'], true)) fail('Choose a valid payment method.');
    submission_slot('checkout', $phone . '|' . ($mail ?: $phone), 8);
    $result = transaction(function (PDO $pdo) use ($cart, $name, $phone, $mail, $address, $customer, $idempotency, $payment, $area, $couponCode): array {
        $requestHash = hash('sha256', json_encode([$cart, $name, $phone, $mail, $address, $area, $payment, $couponCode], JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR));
        $pdo->prepare('INSERT INTO checkout_requests(idempotency_key,request_hash) VALUES(?,?) ON DUPLICATE KEY UPDATE idempotency_key=VALUES(idempotency_key)')->execute([$idempotency, $requestHash]);
        $query = $pdo->prepare('SELECT request_hash,response FROM checkout_requests WHERE idempotency_key=? FOR UPDATE');
        $query->execute([$idempotency]);
        $request = $query->fetch();
        if (!$request || !hash_equals((string) $request['request_hash'], $requestHash)) throw new RuntimeException('This submission conflicts with an earlier request.');
        if ($request['response'] !== null) return json_decode((string) $request['response'], true, 512, JSON_THROW_ON_ERROR);

        $products = state('products', true);
        $settings = state('settings');
        $coupons = state('coupons') ?? [];
        if (!is_array($products) || !is_array($settings) || !is_array($coupons)) throw new RuntimeException('Store is not ready.');
        $paymentKey = ['Cash on Delivery' => 'cod', 'bKash' => 'bkash', 'Nagad' => 'nagad', 'Card (demo)' => 'card'][$payment];
        if (($settings['payments'][$paymentKey] ?? false) !== true) throw new RuntimeException('That payment method is not available. Please choose another.');

        $subtotal = 0.0;
        $lines = [];
        foreach ($cart as $item) {
            if (!is_array($item) || !valid_id((string) ($item['id'] ?? '')) || !is_int($item['qty'] ?? null) || $item['qty'] < 1 || $item['qty'] > 20) throw new RuntimeException('Your cart contains an invalid item.');
            $color = text($item['color'] ?? '', 60);
            $size = text($item['size'] ?? '', 30);
            if (!$color || !$size) throw new RuntimeException('Your cart contains an invalid item.');
            $productIndex = null;
            foreach ($products as $index => $product) if (($product['id'] ?? null) === $item['id'] && ($product['active'] ?? true) !== false) { $productIndex = $index; break; }
            if ($productIndex === null) throw new RuntimeException('A product is no longer available.');
            $product =& $products[$productIndex];
            $price = filter_var($product['price'] ?? null, FILTER_VALIDATE_FLOAT);
            if ($price === false || $price < 0) throw new RuntimeException('A product is no longer available.');
            $quantity = $item['qty'];
            $variants = $product['variants'] ?? [];
            if (is_array($variants) && count($variants) > 0) {
                $variantIndex = null;
                foreach ($variants as $index => $variant) if (($variant['color'] ?? '') === $color && ($variant['size'] ?? '') === $size) { $variantIndex = $index; break; }
                if ($variantIndex === null || (int) ($variants[$variantIndex]['stock'] ?? 0) < $quantity) throw new RuntimeException('One or more items are no longer available in the requested quantity.');
                $product['variants'][$variantIndex]['stock'] = (int) $variants[$variantIndex]['stock'] - $quantity;
                $product['stock'] = array_sum(array_map(static fn(array $variant): int => max(0, (int) ($variant['stock'] ?? 0)), $product['variants']));
            } else {
                $colors = is_array($product['colors'] ?? null) && count($product['colors']) ? $product['colors'] : [($product['color'] ?? 'Black')];
                $sizes = is_array($product['sizes'] ?? null) && count($product['sizes']) ? $product['sizes'] : ['One Size'];
                if (!in_array($color, $colors, true) || !in_array($size, $sizes, true) || (int) ($product['stock'] ?? 0) < $quantity) throw new RuntimeException('One or more items are no longer available in the requested quantity.');
                $product['stock'] = (int) $product['stock'] - $quantity;
            }
            $subtotal += (float) $price * $quantity;
            $lines[] = ['id' => (string) $item['id'], 'name' => text($product['name'] ?? '', 160), 'color' => $color, 'size' => $size, 'qty' => $quantity, 'price' => (float) $price];
            unset($product);
        }
        if (!in_array($area, ['dhaka', 'outside'], true)) throw new RuntimeException('Select a delivery area.');
        $shipping = (float) ($settings[$area] ?? 0);
        if ((float) ($settings['freeThreshold'] ?? 0) > 0 && $subtotal >= (float) $settings['freeThreshold']) $shipping = 0.0;
        $discount = 0.0;
        $couponFound = $couponCode === '';
        foreach ($coupons as $coupon) {
            if (!is_array($coupon) || strtoupper((string) ($coupon['code'] ?? '')) !== strtoupper($couponCode) || ($coupon['active'] ?? false) !== true || $subtotal < (float) ($coupon['minimum'] ?? 0)) continue;
            $couponFound = true;
            $discount = ($coupon['type'] ?? '') === 'percent' ? min($subtotal, round($subtotal * (float) ($coupon['value'] ?? 0) / 100)) : min($subtotal, (float) ($coupon['value'] ?? 0));
            break;
        }
        if (!$couponFound) throw new RuntimeException('Coupon is invalid.');
        $reference = 'SAZ-' . strtoupper(substr(str_replace('-', '', uuid()), 0, 10));
        $orderId = uuid();
        $total = max(0, $subtotal + $shipping - $discount);
        persist_state('products', $products);
        $order = $pdo->prepare('INSERT INTO orders(id,reference,customer_name,phone,email,address,city,district,division,payment_method,subtotal,shipping,discount,total,coupon,status,line_items) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)');
        $order->execute([$orderId, $reference, $name, $phone, $mail ?: null, $address, $area === 'dhaka' ? 'Dhaka' : 'Outside Dhaka', text($customer['district'] ?? '', 100) ?: null, text($customer['division'] ?? '', 100) ?: null, $payment, $subtotal, $shipping, $discount, $total, $couponCode ? strtoupper($couponCode) : null, 'Processing', json_encode($lines, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR)]);
        $lineInsert = $pdo->prepare('INSERT INTO order_items(order_id,product_id,name,color,size,quantity,unit_price) VALUES(?,?,?,?,?,?,?)');
        foreach ($lines as $line) $lineInsert->execute([$orderId, $line['id'], $line['name'], $line['color'], $line['size'], $line['qty'], $line['price']]);
        $result = ['ref' => $reference, 'total' => $total, 'status' => 'Processing'];
        $pdo->prepare('UPDATE checkout_requests SET response=?,order_reference=? WHERE idempotency_key=?')->execute([json_encode($result, JSON_THROW_ON_ERROR), $reference, $idempotency]);
        return $result;
    });
    out(['order' => $result], 201);
}

function state_text_is_valid(mixed $value, int $limit, bool $required = false): bool {
    return is_string($value) && mb_strlen(trim($value)) <= $limit && (!$required || trim($value) !== '');
}

function state_string_list_is_valid(mixed $value, int $countLimit, int $itemLimit): bool {
    if (!is_array($value) || count($value) > $countLimit) return false;
    foreach ($value as $item) if (!state_text_is_valid($item, $itemLimit, true)) return false;
    return true;
}

function state_asset_list_is_valid(mixed $value, int $countLimit = 40): bool {
    if (!is_array($value) || count($value) > $countLimit) return false;
    foreach ($value as $asset) if (!safe_public_asset($asset)) return false;
    return true;
}

function validate_state_value(string $key, mixed $value): void {
    if (in_array($key, ['products', 'product_types', 'coupons', 'home_categories'], true) && !is_array($value)) fail('Invalid store data.');
    if (in_array($key, ['settings', 'site_content', 'page_products'], true) && (!is_array($value) || array_is_list($value))) fail('Invalid store data.');

    if ($key === 'products') {
        if (count($value) > 5000) fail('Too many products.');
        $ids = [];
        foreach ($value as $product) {
            $id = is_array($product) ? (string) ($product['id'] ?? '') : '';
            if (!is_array($product) || !valid_id($id) || isset($ids[$id]) || !state_text_is_valid($product['name'] ?? null, 160, true) || !is_numeric($product['price'] ?? null) || (float) $product['price'] < 0) fail('Invalid product data.');
            $ids[$id] = true;
            foreach (['category' => 100, 'color' => 60, 'type' => 60, 'badge' => 100, 'gender' => 20, 'collection' => 80, 'description' => 10000] as $field => $limit) {
                if (array_key_exists($field, $product) && !state_text_is_valid($product[$field], $limit)) fail('Invalid product data.');
            }
            foreach (['old', 'stock'] as $field) if (array_key_exists($field, $product) && (!is_numeric($product[$field]) || (float) $product[$field] < 0 || ($field === 'stock' && !valid_nonnegative_integer($product[$field])))) fail('Invalid product data.');
            if (array_key_exists('active', $product) && !is_bool($product['active'])) fail('Invalid product data.');
            foreach (['image', 'video'] as $field) if (array_key_exists($field, $product) && !safe_public_asset($product[$field])) fail('Invalid product media.');
            foreach (['images', 'descriptionImages'] as $field) if (array_key_exists($field, $product) && !state_asset_list_is_valid($product[$field])) fail('Invalid product media.');
            foreach (['colors' => 60, 'sizes' => 30] as $field => $limit) if (array_key_exists($field, $product) && !state_string_list_is_valid($product[$field], 100, $limit)) fail('Invalid product options.');
            if (array_key_exists('variants', $product)) {
                if (!is_array($product['variants']) || count($product['variants']) > 250) fail('Invalid variant data.');
                $variants = [];
                foreach ($product['variants'] as $variant) {
                    if (!is_array($variant) || !state_text_is_valid($variant['color'] ?? null, 60, true) || !state_text_is_valid($variant['size'] ?? null, 30, true) || !valid_nonnegative_integer($variant['stock'] ?? null)) fail('Invalid variant data.');
                    $variantKey = $variant['color'] . "\0" . $variant['size'];
                    if (isset($variants[$variantKey])) fail('Duplicate product variant.');
                    $variants[$variantKey] = true;
                }
            }
            if (array_key_exists('variantImages', $product)) {
                if (!is_array($product['variantImages']) || count($product['variantImages']) > 100) fail('Invalid product media.');
                foreach ($product['variantImages'] as $color => $images) if (!state_text_is_valid($color, 60, true) || !state_asset_list_is_valid($images)) fail('Invalid product media.');
            }
        }
        return;
    }

    if ($key === 'product_types') {
        if (!state_string_list_is_valid($value, 200, 60)) fail('Invalid product types.');
        return;
    }

    if ($key === 'coupons') {
        if (count($value) > 1000) fail('Too many coupons.');
        $codes = [];
        foreach ($value as $coupon) {
            $code = is_array($coupon) ? text($coupon['code'] ?? '', 50) : '';
            if (!is_array($coupon) || !preg_match('/^[A-Za-z0-9_-]{1,50}$/', $code) || isset($codes[strtoupper($code)]) || !in_array($coupon['type'] ?? '', ['percent', 'fixed'], true) || !is_numeric($coupon['value'] ?? null) || (float) $coupon['value'] < 0 || !is_numeric($coupon['minimum'] ?? 0) || (float) $coupon['minimum'] < 0 || (array_key_exists('active', $coupon) && !is_bool($coupon['active']))) fail('Invalid coupon data.');
            $codes[strtoupper($code)] = true;
        }
        return;
    }

    if ($key === 'settings') {
        foreach (['dhaka', 'outside', 'freeThreshold'] as $field) if (!is_numeric($value[$field] ?? null) || (float) $value[$field] < 0) fail('Invalid store settings.');
        if (!is_array($value['payments'] ?? null)) fail('Enable at least one payment method.');
        $paymentEnabled = false;
        foreach (['cod', 'bkash', 'nagad', 'card'] as $method) {
            if (array_key_exists($method, $value['payments']) && !is_bool($value['payments'][$method])) fail('Invalid store settings.');
            $paymentEnabled = $paymentEnabled || (($value['payments'][$method] ?? false) === true);
        }
        if (!$paymentEnabled) fail('Enable at least one payment method.');
        foreach (['bkashNumber', 'nagadNumber'] as $field) if (array_key_exists($field, $value) && !state_text_is_valid($value[$field], 60)) fail('Invalid store settings.');
        return;
    }

    if ($key === 'site_content') {
        foreach (['announcement' => 500, 'heroEyebrow' => 160, 'heroTitle' => 500, 'heroText' => 2000, 'heroButton' => 100, 'aboutStory' => 10000, 'footerText' => 2000, 'contactEmail' => 254, 'contactPhone' => 60, 'contactLocation' => 240] as $field => $limit) if (array_key_exists($field, $value) && !state_text_is_valid($value[$field], $limit)) fail('Invalid site content.');
        if (array_key_exists('contactEmail', $value) && $value['contactEmail'] !== '' && !email($value['contactEmail'])) fail('Invalid site content.');
        if (array_key_exists('logoPath', $value) && !safe_public_asset($value['logoPath'])) fail('Invalid site media.');
        if (array_key_exists('carouselSlides', $value)) {
            if (!is_array($value['carouselSlides']) || count($value['carouselSlides']) > 30) fail('Invalid site slideshow.');
            foreach ($value['carouselSlides'] as $slide) if (!is_array($slide) || !safe_public_asset($slide['image'] ?? '') || (array_key_exists('tabletImage', $slide) && $slide['tabletImage'] !== '' && !safe_public_asset($slide['tabletImage'])) || (array_key_exists('mobileImage', $slide) && $slide['mobileImage'] !== '' && !safe_public_asset($slide['mobileImage'])) || !safe_store_link($slide['link'] ?? '') || !state_text_is_valid($slide['title'] ?? '', 240) || !state_text_is_valid($slide['text'] ?? '', 1000) || !state_text_is_valid($slide['button'] ?? '', 100)) fail('Invalid site slideshow.');
        }
        return;
    }

    if ($key === 'page_products') {
        if (count($value) > 100) fail('Invalid product placement.');
        foreach ($value as $section => $ids) {
            if (!state_text_is_valid($section, 60, true) || !is_array($ids) || count($ids) > 5000) fail('Invalid product placement.');
            foreach ($ids as $id) if (!is_string($id) || !valid_id($id)) fail('Invalid product placement.');
        }
        return;
    }

    if ($key === 'home_categories') {
        if (count($value) > 100) fail('Too many homepage categories.');
        foreach ($value as $category) if (!is_array($category) || !state_text_is_valid($category['label'] ?? null, 80, true) || !safe_store_link($category['href'] ?? '') || !safe_public_asset($category['image'] ?? '')) fail('Invalid homepage category.');
    }
}

function variant_key_set(array $product): ?array {
    if (!is_array($product['variants'] ?? null) || count($product['variants']) === 0) return null;
    $keys = [];
    foreach ($product['variants'] as $variant) if (is_array($variant)) $keys[(string) ($variant['color'] ?? '') . "\0" . (string) ($variant['size'] ?? '')] = true;
    return $keys;
}

function assert_product_history_is_preserved(PDO $pdo, array $currentProducts, array $nextProducts): void {
    $nextById = [];
    foreach ($nextProducts as $product) if (is_array($product) && isset($product['id'])) $nextById[(string) $product['id']] = $product;
    $affected = [];
    foreach ($currentProducts as $product) {
        if (!is_array($product) || !isset($product['id'])) continue;
        $id = (string) $product['id'];
        $next = $nextById[$id] ?? null;
        if ($next === null) { $affected[$id] = ['removed' => true, 'old' => null, 'next' => null]; continue; }
        $oldVariants = variant_key_set($product);
        $nextVariants = variant_key_set($next);
        if ($oldVariants !== $nextVariants) $affected[$id] = ['removed' => false, 'old' => $oldVariants, 'next' => $nextVariants];
    }
    if (!$affected) return;
    $ids = array_keys($affected);
    $query = $pdo->prepare('SELECT product_id,color,size FROM order_items WHERE product_id IN (' . implode(',', array_fill(0, count($ids), '?')) . ')');
    $query->execute($ids);
    foreach ($query->fetchAll() as $line) {
        $change = $affected[$line['product_id']];
        if ($change['removed']) throw new RuntimeException('A product used by an order cannot be removed. Mark it inactive instead.');
        $lineKey = (string) $line['color'] . "\0" . (string) $line['size'];
        if ($change['next'] === null || !isset($change['next'][$lineKey])) throw new RuntimeException('Historical order variants must remain available for inventory reconciliation.');
    }
}

function state_save(): never {
    $user = current_user();
    require_csrf();
    $input = request_body();
    $map = ['sazProducts' => ['products', 'products.manage'], 'sazProductTypes' => ['product_types', 'products.manage'], 'sazCoupons' => ['coupons', 'coupons.manage'], 'sazSettings' => ['settings', 'settings.manage'], 'sazSiteContent' => ['site_content', 'content.manage'], 'sazPageProducts' => ['page_products', 'content.manage'], 'sazHomeCategories' => ['home_categories', 'content.manage']];
    $definition = $map[$input['key'] ?? ''] ?? null;
    $expectedRevision = filter_var($input['version'] ?? null, FILTER_VALIDATE_INT);
    if (!$user || !$definition || (!can('store.manage') && !can($definition[1])) || !array_key_exists('value', $input)) fail('You do not have permission to save this content.', 403);
    if ($expectedRevision === false || $expectedRevision < 0) fail('Refresh the store before saving changes.', 409);
    validate_state_value($definition[0], $input['value']);
    $revision = transaction(function (PDO $pdo) use ($definition, $input, $expectedRevision, $user): int {
        $current = state_record($definition[0], true);
        $currentRevision = $current === null ? 0 : $current['revision'];
        if ($currentRevision !== $expectedRevision) throw new RuntimeException('Store data changed. Refresh and try again.');
        $currentProducts = $current !== null && is_array($current['value']) ? $current['value'] : [];
        if ($definition[0] === 'products') assert_product_history_is_preserved($pdo, $currentProducts, $input['value']);
        $nextRevision = persist_state($definition[0], $input['value']);
        audit($user['id'], 'store.state_saved', 'store_state', $definition[0], ['revision' => $nextRevision]);
        return $nextRevision;
    });
    out(['ok' => true, 'version' => $revision]);
}

function orders_read(): never {
    require_permission('orders.view');
    $showCustomer = can('customers.view');
    $rows = db()->query('SELECT reference,customer_name,phone,email,address,city,district,division,payment_method,subtotal,shipping,discount,total,coupon,status,line_items,created_at FROM orders ORDER BY created_at DESC LIMIT 500')->fetchAll();
    if (!$showCustomer) foreach ($rows as &$row) foreach (['customer_name', 'phone', 'email', 'address', 'city', 'district', 'division'] as $column) $row[$column] = null;
    out(['orders' => $rows]);
}

function messages_read(): never {
    require_permission('messages.view');
    out(['messages' => db()->query('SELECT id,name,email,subject,message,created_at FROM contact_messages ORDER BY created_at DESC LIMIT 500')->fetchAll()]);
}

function update_order_inventory(PDO $pdo, array $order, string $nextStatus): void {
    $current = $order['status'];
    if ($current === $nextStatus || ($current !== 'Cancelled' && $nextStatus !== 'Cancelled')) return;
    $direction = $nextStatus === 'Cancelled' ? 1 : -1;
    $products = state('products', true);
    if (!is_array($products)) throw new RuntimeException('Store inventory is unavailable.');
    foreach (json_decode((string) $order['line_items'], true, 512, JSON_THROW_ON_ERROR) as $line) {
        $found = false;
        foreach ($products as &$product) {
            if (($product['id'] ?? '') !== ($line['id'] ?? '')) continue;
            $found = true;
            $quantity = (int) ($line['qty'] ?? 0);
            if ($quantity < 1) throw new RuntimeException('Store inventory is unavailable.');
            if (is_array($product['variants'] ?? null) && count($product['variants'])) {
                $variantFound = false;
                foreach ($product['variants'] as &$variant) {
                    if (($variant['color'] ?? '') !== ($line['color'] ?? '') || ($variant['size'] ?? '') !== ($line['size'] ?? '')) continue;
                    $variantFound = true;
                    if ($direction < 0 && (int) ($variant['stock'] ?? 0) < $quantity) throw new RuntimeException('Insufficient stock to reactivate this order.');
                    $variant['stock'] = (int) $variant['stock'] + ($direction * $quantity);
                    break;
                }
                unset($variant);
                if (!$variantFound) throw new RuntimeException('The ordered variant no longer exists.');
                $product['stock'] = array_sum(array_map(static fn(array $variant): int => max(0, (int) ($variant['stock'] ?? 0)), $product['variants']));
            } else {
                if ($direction < 0 && (int) ($product['stock'] ?? 0) < $quantity) throw new RuntimeException('Insufficient stock to reactivate this order.');
                $product['stock'] = (int) $product['stock'] + ($direction * $quantity);
            }
            break;
        }
        unset($product);
        if (!$found) throw new RuntimeException('The ordered product no longer exists.');
    }
    persist_state('products', $products);
}

function order_status(): never {
    $user = require_permission('orders.manage');
    require_csrf();
    $input = request_body();
    $reference = text($input['reference'] ?? '', 32);
    $status = text($input['status'] ?? '', 20);
    if (!in_array($status, ['Processing', 'Shipped', 'Delivered', 'Cancelled'], true)) fail('Choose a valid order status.');
    transaction(function (PDO $pdo) use ($reference, $status, $user): void {
        $query = $pdo->prepare('SELECT id,status,line_items FROM orders WHERE reference=? FOR UPDATE');
        $query->execute([$reference]);
        $order = $query->fetch();
        if (!$order) throw new RuntimeException('That order no longer exists.');
        update_order_inventory($pdo, $order, $status);
        $pdo->prepare('UPDATE orders SET status=? WHERE reference=?')->execute([$status, $reference]);
        audit($user['id'], 'order.status_changed', 'order', $reference, ['status' => $status]);
    });
    out(['ok' => true]);
}

const SAZ_PERMISSIONS = ['admin.access', 'dashboard.view', 'orders.view', 'orders.manage', 'products.manage', 'coupons.manage', 'messages.view', 'messages.manage', 'content.manage', 'settings.manage', 'store.manage', 'customers.view'];

function slugify_role(string $name): string {
    $slug = strtolower(trim(preg_replace('/[^a-z0-9]+/i', '-', $name) ?? ''));
    return substr(trim($slug, '-'), 0, 48);
}

function staff_permissions(array $input): array {
    $received = is_array($input['permissions'] ?? null) ? $input['permissions'] : [];
    $permissions = array_values(array_unique(array_filter($received, static fn($value): bool => is_string($value) && in_array($value, SAZ_PERMISSIONS, true))));
    if (!in_array('admin.access', $permissions, true)) fail('Every staff role must include Admin panel access.');
    foreach (['orders.manage' => 'orders.view', 'customers.view' => 'orders.view', 'messages.manage' => 'messages.view'] as $permission => $dependency) {
        if (in_array($permission, $permissions, true) && !in_array($dependency, $permissions, true)) fail("$permission requires $dependency.");
    }
    return $permissions;
}

function dashboard(): array {
    $pdo = db();
    $roles = $pdo->query('SELECT slug,name,description,permissions,is_protected,created_at,updated_at FROM roles ORDER BY is_protected DESC,name')->fetchAll();
    foreach ($roles as &$role) $role['permissions'] = json_decode((string) $role['permissions'], true) ?: [];
    unset($role);
    $staff = $pdo->query("SELECT id,email,role_slug AS role,is_active,created_at,last_sign_in_at,NULL AS banned_until FROM users ORDER BY email")->fetchAll();
    $audit = $pdo->query('SELECT id,action,target_type,target_id,details,created_at FROM admin_audit_log ORDER BY created_at DESC LIMIT 20')->fetchAll();
    $passwordEvents = $pdo->query("SELECT action,target_id,created_at FROM admin_audit_log WHERE action IN ('staff.created','staff.password_changed') ORDER BY created_at DESC LIMIT 1000")->fetchAll();
    return compact('roles', 'staff', 'audit', 'passwordEvents');
}

function role_exists(PDO $pdo, string $slug, bool $staffOnly = false): bool {
    $query = $pdo->prepare('SELECT slug FROM roles WHERE slug=?' . ($staffOnly ? " AND slug<>'customer'" : ''));
    $query->execute([$slug]);
    return (bool) $query->fetch();
}

function active_owner_count(PDO $pdo): int {
    return (int) $pdo->query("SELECT COUNT(*) FROM users WHERE role_slug='owner' AND is_active=1 FOR UPDATE")->fetchColumn();
}

function access(): never {
    $actor = require_permission('admin.access');
    if ($actor['role_slug'] !== 'owner') fail('Only an Owner can manage staff access.', 403);
    require_csrf();
    $input = request_body();
    $action = text($input['action'] ?? '', 32);
    if ($action === 'overview') out(['data' => dashboard()]);

    if ($action === 'save_role') {
        $name = text($input['name'] ?? '', 80);
        $description = text($input['description'] ?? '', 240);
        $slug = text($input['slug'] ?? '', 48);
        if (mb_strlen($name) < 2) fail('A role name must have at least two characters.');
        $permissions = staff_permissions($input);
        transaction(function (PDO $pdo) use ($actor, $name, $description, $slug, $permissions): void {
            if ($slug !== '') {
                $query = $pdo->prepare('SELECT is_protected FROM roles WHERE slug=? FOR UPDATE');
                $query->execute([$slug]);
                $role = $query->fetch();
                if (!$role) throw new RuntimeException('That role no longer exists.');
                if ((bool) $role['is_protected']) throw new RuntimeException('Protected Owner and Customer roles cannot be edited.');
                $pdo->prepare('UPDATE roles SET name=?,description=?,permissions=? WHERE slug=?')->execute([$name, $description, json_encode($permissions, JSON_THROW_ON_ERROR), $slug]);
                audit($actor['id'], 'role.updated', 'role', $slug, ['name' => $name, 'permissions' => $permissions]);
                return;
            }
            $newSlug = slugify_role($name);
            if (strlen($newSlug) < 2) throw new RuntimeException('Use letters or numbers in the role name.');
            $pdo->prepare('INSERT INTO roles(slug,name,description,permissions) VALUES(?,?,?,?)')->execute([$newSlug, $name, $description, json_encode($permissions, JSON_THROW_ON_ERROR)]);
            audit($actor['id'], 'role.created', 'role', $newSlug, ['name' => $name, 'permissions' => $permissions]);
        });
    } elseif ($action === 'delete_role') {
        $slug = text($input['slug'] ?? '', 48);
        transaction(function (PDO $pdo) use ($actor, $slug): void {
            $query = $pdo->prepare('SELECT is_protected FROM roles WHERE slug=? FOR UPDATE');
            $query->execute([$slug]);
            $role = $query->fetch();
            if (!$role) throw new RuntimeException('That role no longer exists.');
            if ((bool) $role['is_protected']) throw new RuntimeException('Protected roles cannot be deleted.');
            $count = $pdo->prepare('SELECT COUNT(*) FROM users WHERE role_slug=? FOR UPDATE');
            $count->execute([$slug]);
            if ((int) $count->fetchColumn() > 0) throw new RuntimeException('Move every team member to another role before deleting this role.');
            $pdo->prepare('DELETE FROM roles WHERE slug=?')->execute([$slug]);
            audit($actor['id'], 'role.deleted', 'role', $slug);
        });
    } elseif ($action === 'create_staff') {
        $mail = email($input['email'] ?? null);
        $role = text($input['role'] ?? '', 48);
        $password = strong_password($input['password'] ?? null);
        if (!$mail || !valid_id($role)) fail('Enter a valid staff email and role.');
        transaction(function (PDO $pdo) use ($actor, $mail, $role, $password): void {
            if (!role_exists($pdo, $role, true)) throw new RuntimeException('Choose a valid staff role.');
            $id = uuid();
            $pdo->prepare('INSERT INTO users(id,email,password_hash,role_slug) VALUES(?,?,?,?)')->execute([$id, $mail, password_hash($password, PASSWORD_DEFAULT), $role]);
            audit($actor['id'], 'staff.created', 'user', $id, ['email' => $mail, 'role' => $role]);
        });
    } elseif ($action === 'assign_role') {
        $id = text($input['userId'] ?? '', 36);
        $role = text($input['role'] ?? '', 48);
        transaction(function (PDO $pdo) use ($actor, $id, $role): void {
            if (!role_exists($pdo, $role)) throw new RuntimeException('Choose a valid role.');
            $query = $pdo->prepare('SELECT role_slug,is_active FROM users WHERE id=? FOR UPDATE');
            $query->execute([$id]);
            $target = $query->fetch();
            if (!$target) throw new RuntimeException('That team member no longer exists.');
            if ($target['role_slug'] === 'owner' && $role !== 'owner' && (bool) $target['is_active'] && active_owner_count($pdo) <= 1) throw new RuntimeException('At least one active Owner must always remain.');
            $pdo->prepare('UPDATE users SET role_slug=? WHERE id=?')->execute([$role, $id]);
            audit($actor['id'], 'staff.role_changed', 'user', $id, ['from' => $target['role_slug'], 'to' => $role]);
        });
    } elseif ($action === 'set_staff_password') {
        $id = text($input['userId'] ?? '', 36);
        $password = strong_password($input['password'] ?? null);
        $query = db()->prepare('UPDATE users SET password_hash=? WHERE id=?');
        $query->execute([password_hash($password, PASSWORD_DEFAULT), $id]);
        if ($query->rowCount() !== 1) fail('That team member no longer exists.');
        audit($actor['id'], 'staff.password_changed', 'user', $id);
    } elseif ($action === 'set_status') {
        $id = text($input['userId'] ?? '', 36);
        $active = ($input['active'] ?? false) === true;
        transaction(function (PDO $pdo) use ($actor, $id, $active): void {
            $query = $pdo->prepare('SELECT role_slug,is_active FROM users WHERE id=? FOR UPDATE');
            $query->execute([$id]);
            $target = $query->fetch();
            if (!$target) throw new RuntimeException('That team member no longer exists.');
            if (!$active && (bool) $target['is_active'] && $target['role_slug'] === 'owner' && active_owner_count($pdo) <= 1) throw new RuntimeException('The final active Owner cannot be suspended.');
            $pdo->prepare('UPDATE users SET is_active=? WHERE id=?')->execute([$active ? 1 : 0, $id]);
            audit($actor['id'], $active ? 'staff.activated' : 'staff.suspended', 'user', $id);
        });
    } elseif ($action === 'delete_staff') {
        $id = text($input['userId'] ?? '', 36);
        if ($id === $actor['id']) fail('An Owner cannot delete their own account.');
        transaction(function (PDO $pdo) use ($actor, $id): void {
            $query = $pdo->prepare('SELECT role_slug FROM users WHERE id=? FOR UPDATE');
            $query->execute([$id]);
            $target = $query->fetch();
            if (!$target) throw new RuntimeException('That team member no longer exists.');
            if ($target['role_slug'] === 'owner') throw new RuntimeException('Owner accounts cannot be deleted. Assign another role or suspend the account instead.');
            $pdo->prepare('DELETE FROM users WHERE id=?')->execute([$id]);
            audit($actor['id'], 'staff.deleted', 'user', $id);
        });
    } else {
        fail('Unknown access-control action.');
    }
    out(['data' => dashboard()]);
}

function upload_image(): never {
    $scope = text($_POST['scope'] ?? 'products', 20);
    $user = require_permission($scope === 'content' ? 'content.manage' : 'products.manage');
    require_csrf();
    $file = $_FILES['file'] ?? null;
    if (!is_array($file)) fail('Choose a valid image file.');
    $uploadError = (int) ($file['error'] ?? UPLOAD_ERR_NO_FILE);
    if ($uploadError === UPLOAD_ERR_INI_SIZE || $uploadError === UPLOAD_ERR_FORM_SIZE) fail('The server rejected this image before validation. Use a smaller file or increase PHP upload_max_filesize.', 413);
    if ($uploadError !== UPLOAD_ERR_OK || !is_uploaded_file((string) ($file['tmp_name'] ?? ''))) fail('Choose a valid image file.');
    $limit = (int) (cfg()['max_upload_bytes'] ?? 5242880);
    if ((int) $file['size'] < 1 || (int) $file['size'] > $limit) fail('Use an image smaller than 5 MB.', 413);
    $image = trusted_image_metadata((string) $file['tmp_name']);
    if ($image === null) fail('Use a valid JPG, PNG, or WebP image.');
    $mime = $image['mime'];
    $month = gmdate('Y/m');
    $root = rtrim((string) cfg()['upload_dir'], DIRECTORY_SEPARATOR);
    $directory = $root . DIRECTORY_SEPARATOR . $month;
    if (!is_dir($directory) && !mkdir($directory, 0755, true) && !is_dir($directory)) throw new RuntimeException('Upload storage is unavailable.');
    $name = bin2hex(random_bytes(20)) . '.' . $image['extension'];
    $destination = $directory . DIRECTORY_SEPARATOR . $name;
    if (!move_uploaded_file((string) $file['tmp_name'], $destination)) throw new RuntimeException('Upload storage is unavailable.');
    @chmod($destination, 0644);
    $path = trim((string) cfg()['upload_url'], '/') . '/' . $month . '/' . $name;
    $query = db()->prepare('INSERT INTO media_uploads(id,stored_name,relative_path,mime_type,byte_size,uploaded_by) VALUES(?,?,?,?,?,?)');
    $query->execute([uuid(), $name, $path, $mime, (int) $file['size'], $user['id']]);
    audit($user['id'], 'media.uploaded', 'media', $path, ['mime' => $mime, 'bytes' => (int) $file['size'], 'scope' => $scope]);
    out(['url' => '/' . $path], 201);
}
