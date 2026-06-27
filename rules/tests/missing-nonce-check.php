<?php
/**
 * Test fixtures for wp-missing-nonce-check.
 *
 * Positive patterns sourced from real CVE disclosures:
 *   P1 — CVE-2021-24715 style (nopriv handler reads $_POST, no nonce)
 *   P2 — CVE-2022-0906 style (settings save, no nonce)
 *   P3 — admin_post_ handler reads $_REQUEST, no nonce
 *
 * PHP superglobals in WordPress CVEs are almost always accessed as
 * assignments or direct function arguments, so both forms are tested.
 */

// ============================================================
// POSITIVES — must trigger wp-missing-nonce-check
// ============================================================

// Positive 1 (CVE-2021-24715 pattern):
//   nopriv AJAX handler reads $_POST without any nonce check.
// ruleid: wp-missing-nonce-check
add_action('wp_ajax_nopriv_get_record', function () {
    $id   = $_POST['id'];
    $data = get_option('record_' . $id);
    wp_send_json_success($data);
    wp_die();
});

// Positive 2 (CVE-2022-0906 pattern):
//   privileged AJAX handler writes options from $_POST, no nonce.
// ruleid: wp-missing-nonce-check
add_action('wp_ajax_save_plugin_settings', function () {
    foreach ($_POST['settings'] as $k => $v) {
        update_option(sanitize_key($k), sanitize_text_field($v));
    }
    wp_die('1');
});

// Positive 3:
//   admin_post_ handler reads $_REQUEST without any nonce.
// ruleid: wp-missing-nonce-check
add_action('admin_post_export_users', function () {
    $role  = $_REQUEST['role'];
    $users = get_users(['role' => $role]);
    echo wp_json_encode($users);
    exit;
});

// ============================================================
// NEGATIVES — must NOT trigger wp-missing-nonce-check
// ============================================================

// Negative 1: wp_verify_nonce present before consuming input.
// ok: wp-missing-nonce-check
add_action('wp_ajax_safe_update', function () {
    wp_verify_nonce($_POST['_wpnonce'], 'safe_update');
    $val = sanitize_text_field($_POST['value']);
    update_option('my_option', $val);
    wp_die();
});

// Negative 2: check_ajax_referer present.
// ok: wp-missing-nonce-check
add_action('wp_ajax_safe_delete', function () {
    check_ajax_referer('safe_delete', 'security');
    $id = absint($_POST['id']);
    wp_delete_post($id, true);
    wp_die();
});

// Negative 3: check_admin_referer present (common in admin_post_ handlers).
// ok: wp-missing-nonce-check
add_action('admin_post_safe_export', function () {
    check_admin_referer('safe_export', '_wpnonce');
    $format = sanitize_key($_GET['format']);
    export_data($format);
    exit;
});

// Negative 4: callback reads no user input at all (read-only).
// ok: wp-missing-nonce-check
add_action('wp_ajax_get_stats', function () {
    $count = (int) get_option('view_count', 0);
    wp_send_json_success(['count' => $count]);
});

// Negative 5: non-AJAX hook — 'init' does not match the regex filter.
// ok: wp-missing-nonce-check
add_action('init', function () {
    $val = $_POST['val'] ?? '';
    do_something($val);
});
