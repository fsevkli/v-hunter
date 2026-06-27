<?php
/**
 * Test fixtures for wp-reflected-xss (taint mode).
 * Annotations go immediately before the sink line.
 *
 * Positives sourced from real CVE patterns:
 *   P1 — CVE-2021-24340 style (plugin echoes $_GET param directly)
 *   P2 — search result page echoes $_REQUEST['s'] without escaping
 *   P3 — error message prints $_POST value unescaped
 */

// ============================================================
// POSITIVES — must trigger wp-reflected-xss
// ============================================================

// Positive 1 (CVE-2021-24340 pattern): direct echo of $_GET parameter.
$tab = $_GET['tab'];
// ruleid: wp-reflected-xss
echo $tab;

// Positive 2: search query reflected into page without escaping.
$search = $_REQUEST['s'];
// ruleid: wp-reflected-xss
echo '<p>Search results for: ' . $search . '</p>';

// Positive 3: error message from $_POST reflected in wp_die.
$msg = $_POST['message'];
// ruleid: wp-reflected-xss
wp_die($msg);

// Positive 4 (CVE-2021-24340 pattern): $_SERVER HTTP header echoed directly.
// HTTP_X_FORWARDED_FOR and similar headers are fully user-controllable.
$method = $_SERVER['HTTP_X_FORWARDED_FOR'];
// ruleid: wp-reflected-xss
echo $method;

// Positive 5: filter_input(INPUT_SERVER) — same attack surface via PHP native API.
$ip = filter_input(INPUT_SERVER, 'HTTP_CF_CONNECTING_IP');
// ruleid: wp-reflected-xss
echo $ip;

// ============================================================
// NEGATIVES — must NOT trigger wp-reflected-xss
// ============================================================

// Negative 1: esc_html() applied.
$name = $_GET['name'];
// ok: wp-reflected-xss
echo esc_html($name);

// Negative 2: esc_attr() used in an HTML attribute context.
$val = $_GET['value'];
// ok: wp-reflected-xss
echo '<input value="' . esc_attr($val) . '">';

// Negative 3: sanitize_text_field() strips tags.
$field = $_POST['field'];
// ok: wp-reflected-xss
echo sanitize_text_field($field);

// Negative 4: intval() for numeric output.
$count = $_GET['count'];
// ok: wp-reflected-xss
echo intval($count);

// Negative 5: wp_kses_post() allows safe HTML.
$content = $_POST['content'];
// ok: wp-reflected-xss
echo wp_kses_post($content);
