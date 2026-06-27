<?php
$_SERVER['HTTP_HOST'] = 'localhost';
$_SERVER['REQUEST_URI'] = '/';

// Simulate what WordPress does before plugins load
$_POST['subscriberemail'] = "' OR SLEEP(3) -- -";

// This is what wp_magic_quotes() does
$slashed = addslashes($_POST['subscriberemail']);
echo "Raw input:    " . $_POST['subscriberemail'] . PHP_EOL;
echo "After addslashes: " . $slashed . PHP_EOL;

// What sanitize_text_field does to the slashed value
require('/var/www/html/wp-load.php');
// After wp-load, $_POST is already slashed
echo "Actual \$_POST['subscriberemail']: " . $_POST['subscriberemail'] . PHP_EOL;

$email = sanitize_text_field($_POST['subscriberemail']);
echo "After sanitize_text_field: " . $email . PHP_EOL;

// What the actual query looks like
global $wpdb;
$table_name = $wpdb->prefix . 'sfba_subscribers_lists';
$query = "SELECT * FROM `$table_name` WHERE `email` = '$email'";
echo "Query: " . $query . PHP_EOL;

// Check wpdb's charset
echo "DB charset: " . $wpdb->charset . PHP_EOL;
echo "DB collate: " . $wpdb->collate . PHP_EOL;
