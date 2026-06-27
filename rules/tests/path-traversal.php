<?php
/**
 * Test fixtures for wp-path-traversal (taint mode).
 * Annotations immediately before the sink line.
 *
 * Positives sourced from real CVE patterns:
 *   P1 — CVE-2021-24239 style (plugin reads template file from $_GET param)
 *   P2 — log viewer reads file path from $_POST without traversal check
 *   P3 — include() with user-controlled module name
 */

// ============================================================
// POSITIVES — must trigger wp-path-traversal
// ============================================================

// Positive 1 (CVE-2021-24239 pattern): file read with user-controlled path.
$template = $_GET['template'];
// ruleid: wp-path-traversal
$content  = file_get_contents(WP_CONTENT_DIR . '/templates/' . $template);

// Positive 2: log viewer reads file path from $_POST.
$log_file = $_POST['log'];
// ruleid: wp-path-traversal
readfile('/var/log/' . $log_file);

// Positive 3: include with user-controlled module name.
$module = $_GET['module'];
// ruleid: wp-path-traversal
include WP_PLUGIN_DIR . '/my-plugin/modules/' . $module . '.php';

// ============================================================
// NEGATIVES — must NOT trigger wp-path-traversal
// ============================================================

// Negative 1: realpath() resolves and canonicalizes the path.
$file = $_GET['file'];
$path = realpath(WP_CONTENT_DIR . '/' . $file);
// ok: wp-path-traversal
$data = file_get_contents($path);

// Negative 2: basename() strips directory components.
$name = $_GET['name'];
$safe = basename($name);
// ok: wp-path-traversal
$body = file_get_contents(WP_CONTENT_DIR . '/assets/' . $safe);

// Negative 3: sanitize_file_name() removes traversal characters.
$fname = sanitize_file_name($_POST['filename']);
// ok: wp-path-traversal
$out   = file_get_contents(WP_UPLOADS_DIR . '/' . $fname);

// Negative 4: hardcoded path, no user input.
// ok: wp-path-traversal
$config = file_get_contents(WP_CONTENT_DIR . '/config.json');
