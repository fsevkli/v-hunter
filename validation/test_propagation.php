<?php
global $wpdb;

// SQLI-1: direct superglobal -> SQL
$r1 = $wpdb->get_results("SELECT * WHERE id = " . $_GET['id']);

// SQLI-2: one-step assignment -> SQL
$id = $_GET['id'];
$r2 = $wpdb->get_results("SELECT * WHERE id = $id");

// SQLI-3: wrapper call with superglobal arg -> SQL
$id2 = trim($_GET['id2']);
$r3 = $wpdb->get_results("SELECT * WHERE id = $id2");

// SQLI-4: ternary with superglobal -> SQL
$id3 = isset($_GET['id3']) ? $_GET['id3'] : 0;
$r4 = $wpdb->get_results("SELECT * WHERE id = $id3");

// XSS-1: direct
echo $_GET['x'];

// XSS-2: one-step assignment
$x = $_GET['x2'];
echo $x;

// XSS-3: wrapper call with superglobal arg
$y = trim($_GET['y']);
echo $y;

// XSS-4: ternary with superglobal
$z = isset($_GET['z']) ? $_GET['z'] : 'default';
echo $z;
