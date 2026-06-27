<?php
/**
 * Test fixtures for wp-php-object-injection (taint mode).
 * Annotations immediately before the sink line.
 *
 * Positives sourced from real CVE patterns:
 *   P1 — CVE-2021-24826 style (cookie value passed to unserialize)
 *   P2 — $_POST data deserialized directly
 *   P3 — $_GET param decoded then unserialized
 */

// ============================================================
// POSITIVES — must trigger wp-php-object-injection
// ============================================================

// Positive 1 (CVE-2021-24826 pattern): cookie value passed to unserialize.
$cart = $_COOKIE['cart'];
// ruleid: wp-php-object-injection
$data = unserialize($cart);

// Positive 2: $_POST data deserialized directly.
$payload = $_POST['data'];
// ruleid: wp-php-object-injection
$obj = unserialize($payload);

// Positive 3: base64-decoded $_GET value then unserialized.
$encoded = $_GET['obj'];
$raw     = base64_decode($encoded);
// ruleid: wp-php-object-injection
$result  = unserialize($raw);

// Positive 4: maybe_unserialize() on a $_POST value — equally dangerous.
$meta_raw = $_POST['meta_value'];
// ruleid: wp-php-object-injection
$meta_obj = maybe_unserialize($meta_raw);

// ============================================================
// NEGATIVES — must NOT trigger wp-php-object-injection
// ============================================================

// Negative 1: deserializing a hardcoded/trusted string.
// ok: wp-php-object-injection
$trusted = unserialize('O:8:"stdClass":0:{}');

// Negative 2: deserializing a value from the WordPress options table (trusted).
$stored = get_option('my_serialized_option');
// ok: wp-php-object-injection
$obj    = unserialize($stored);

// Negative 3: json_decode used instead of unserialize (safe).
$raw_json = $_POST['data'];
// ok: wp-php-object-injection
$safe_obj = json_decode($raw_json, true);

// Negative 4: unserialize on a server-side transient (trusted source).
$transient = get_transient('my_data_cache');
// ok: wp-php-object-injection
$cached    = unserialize($transient);
