<?php
/**
 * Test fixtures for wp-missing-cap-check.
 *
 * Positives sourced from real CVE patterns:
 *   P1 — CVE-2021-24762 style (GiveWP ajax handler, no cap check)
 *   P2 — settings update ajax handler accessible by any logged-in user
 *   P3 — admin_post_ handler deletes data without cap check
 */

// ============================================================
// POSITIVES — must trigger wp-missing-cap-check
// ============================================================

// Positive 1 (CVE-2021-24762 pattern):
//   Authenticated (subscriber+) AJAX handler reads $_POST, no cap check.
// ruleid: wp-missing-cap-check
add_action('wp_ajax_get_donor_info', function () {
    $id   = $_POST['donor_id'];
    $info = get_user_meta($id, 'donor_data', true);
    wp_send_json_success($info);
    wp_die();
});

// Positive 2:
//   AJAX handler saves plugin options; any logged-in user can call it.
// ruleid: wp-missing-cap-check
add_action('wp_ajax_save_display_options', function () {
    $opts = $_POST['options'];
    update_option('my_plugin_display', sanitize_text_field($opts));
    wp_die();
});

// Positive 3:
//   admin_post_ handler deletes a record without checking admin capability.
// ruleid: wp-missing-cap-check
add_action('admin_post_delete_record', function () {
    $rid = absint($_GET['record_id']);
    delete_record($rid);
    wp_redirect(admin_url());
    exit;
});

// ============================================================
// NEGATIVES — must NOT trigger wp-missing-cap-check
// ============================================================

// Negative 1: current_user_can() check present.
// ok: wp-missing-cap-check
add_action('wp_ajax_admin_only_action', function () {
    if (!current_user_can('manage_options')) {
        wp_die('Forbidden', 403);
    }
    $val = sanitize_text_field($_POST['value']);
    update_option('my_option', $val);
    wp_die();
});

// Negative 2: user_can() check present.
// ok: wp-missing-cap-check
add_action('wp_ajax_edit_post_action', function () {
    $post_id = absint($_POST['post_id']);
    if (!user_can(get_current_user_id(), 'edit_post', $post_id)) {
        wp_die('Forbidden', 403);
    }
    save_post_data($post_id, $_POST['data']);
    wp_die();
});

// Negative 3: nopriv hook — public by design, no cap check expected.
// ok: wp-missing-cap-check
add_action('wp_ajax_nopriv_public_search', function () {
    $q = sanitize_text_field($_GET['q']);
    $results = search_public_data($q);
    wp_send_json_success($results);
});

// Negative 4: no user input accessed.
// ok: wp-missing-cap-check
add_action('wp_ajax_get_my_count', function () {
    $count = (int) get_option('item_count', 0);
    wp_send_json_success(['count' => $count]);
});

// Negative 5: non-AJAX hook.
// ok: wp-missing-cap-check
add_action('admin_init', function () {
    $val = $_POST['setting'] ?? '';
    update_option('something', $val);
});
