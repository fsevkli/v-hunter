<?php
$_SERVER['HTTP_HOST'] = 'localhost';
$_SERVER['REQUEST_URI'] = '/';
require('/var/www/html/wp-load.php');

// Create subscribe form CPT post with database mode
$form_id = wp_insert_post([
    'post_title'  => 'Test Subscribe Form',
    'post_type'   => 'sfba_subscribe_form',
    'post_status' => 'publish',
]);
update_post_meta($form_id, '_sfba_subscription_selection_dd', 'database');
echo "Form ID: $form_id" . PHP_EOL;

// Verify the table exists
global $wpdb;
$table = $wpdb->prefix . 'sfba_subscribers_lists';
$exists = $wpdb->get_var("SHOW TABLES LIKE '$table'");
echo "Table exists: " . ($exists ? 'YES' : 'NO') . PHP_EOL;

// Show actual columns
$cols = $wpdb->get_results("SHOW COLUMNS FROM `$table`");
echo "Columns (" . count($cols) . "):" . PHP_EOL;
foreach ($cols as $col) {
    echo "  - " . $col->Field . " (" . $col->Type . ")" . PHP_EOL;
}

// Confirm post meta
$mode = get_post_meta($form_id, '_sfba_subscription_selection_dd', true);
echo "Send mode: $mode" . PHP_EOL;
