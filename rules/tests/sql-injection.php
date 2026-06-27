<?php
/**
 * Test fixtures for wp-sqli (taint mode).
 * Annotations go on the line immediately before the sink expression.
 *
 * Positives sourced from real CVE patterns:
 *   P1 — CVE-2024-1071 (Ultimate Member — ORDER BY injection via $_GET)
 *   P2 — CVE-2021-24762 (Perfect Survey — unsanitized id in get_var)
 *   P3 — CVE-2022-4328  (direct $_POST concat into wpdb->query)
 */
global $wpdb;

// ============================================================
// POSITIVES — must trigger wp-sqli
// ============================================================

// Positive 1 (CVE-2024-1071): ORDER BY from $_GET, no sanitization.
$order = $_GET['order'];
// ruleid: wp-sqli
$results = $wpdb->get_results("SELECT * FROM {$wpdb->users} ORDER BY $order");

// Positive 2 (CVE-2021-24762): survey id from $_GET in get_var.
$id = $_GET['id'];
// ruleid: wp-sqli
$answer = $wpdb->get_var("SELECT answer FROM {$wpdb->prefix}survey WHERE id = $id");

// Positive 3 (CVE-2022-4328): $_POST concat into query.
$status = $_POST['status'];
// ruleid: wp-sqli
$wpdb->query("UPDATE {$wpdb->prefix}orders SET status = '$status' WHERE id = 1");

// Positive 4: filter_input(INPUT_GET) used as source — one-level wrapper propagation.
$cat = filter_input(INPUT_GET, 'cat');
// ruleid: wp-sqli
$rows = $wpdb->get_results("SELECT * FROM {$wpdb->prefix}posts WHERE cat = $cat");

// ============================================================
// NEGATIVES — must NOT trigger wp-sqli
// ============================================================

// Negative 1: intval() sanitizes the integer id.
$id_safe = intval($_GET['id']);
// ok: wp-sqli
$row = $wpdb->get_row("SELECT * FROM {$wpdb->prefix}items WHERE id = $id_safe");

// Negative 2: absint() sanitizes the integer.
$uid = absint($_POST['user_id']);
// ok: wp-sqli
$data = $wpdb->get_var("SELECT meta FROM {$wpdb->usermeta} WHERE user_id = $uid");

// Negative 3: $wpdb->prepare() used correctly.
$email = $_POST['email'];
// ok: wp-sqli
$user = $wpdb->get_row($wpdb->prepare(
    "SELECT * FROM {$wpdb->users} WHERE user_email = %s",
    $email
));

// Negative 4: esc_sql() applied before use.
$slug = esc_sql($_GET['slug']);
// ok: wp-sqli
$post = $wpdb->get_var("SELECT ID FROM {$wpdb->posts} WHERE post_name = '$slug'");

// Negative 5: sanitize_key() used (safe for identifiers).
$col = sanitize_key($_GET['col']);
// ok: wp-sqli
$rows = $wpdb->get_results("SELECT $col FROM {$wpdb->prefix}meta");
