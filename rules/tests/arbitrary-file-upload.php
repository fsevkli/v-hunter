<?php
/**
 * Test fixtures for wp-arbitrary-file-upload.
 * Annotations go before the function definition (function-level match).
 *
 * Positives sourced from real CVE patterns:
 *   P1 — CVE-2020-8637 style (direct move_uploaded_file, no type check)
 *   P2 — plugin uploads avatar with only size check, no extension check
 *   P3 — import handler moves file without MIME validation
 */

// ============================================================
// POSITIVES — must trigger wp-arbitrary-file-upload
// ============================================================

// Positive 1 (CVE-2020-8637 pattern): move_uploaded_file, no type check.
// ruleid: wp-arbitrary-file-upload
function handle_upload_insecure() {
    $tmp  = $_FILES['file']['tmp_name'];
    $dest = WP_CONTENT_DIR . '/uploads/' . $_FILES['file']['name'];
    move_uploaded_file($tmp, $dest);
}

// Positive 2: avatar upload checks only size, not extension or MIME.
// ruleid: wp-arbitrary-file-upload
function save_avatar_insecure() {
    if ($_FILES['avatar']['size'] > 2000000) {
        wp_die('Too large');
    }
    $tmp  = $_FILES['avatar']['tmp_name'];
    $dest = get_avatar_dir() . '/' . $_FILES['avatar']['name'];
    move_uploaded_file($tmp, $dest);
}

// Positive 3: import handler sanitizes filename but skips MIME/extension check.
// ruleid: wp-arbitrary-file-upload
function import_file_insecure() {
    $name = sanitize_file_name($_FILES['import']['name']);
    $tmp  = $_FILES['import']['tmp_name'];
    move_uploaded_file($tmp, WP_CONTENT_DIR . '/imports/' . $name);
}

// ============================================================
// NEGATIVES — must NOT trigger wp-arbitrary-file-upload
// ============================================================

// Negative 1: wp_check_filetype() validates extension before move.
// ok: wp-arbitrary-file-upload
function handle_upload_safe_1() {
    $name    = $_FILES['file']['name'];
    $tmp     = $_FILES['file']['tmp_name'];
    $allowed = wp_check_filetype($name, null);
    if (!$allowed['ext']) {
        wp_die('Invalid file type');
    }
    move_uploaded_file($tmp, WP_CONTENT_DIR . '/uploads/' . $name);
}

// Negative 2: PATHINFO_EXTENSION + allowlist check.
// ok: wp-arbitrary-file-upload
function handle_upload_safe_2() {
    $ext     = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
    $allowed = ['jpg', 'png', 'gif', 'pdf'];
    if (!in_array(strtolower($ext), $allowed)) {
        wp_die('Extension not allowed');
    }
    $tmp  = $_FILES['file']['tmp_name'];
    $dest = WP_CONTENT_DIR . '/uploads/' . sanitize_file_name($_FILES['file']['name']);
    move_uploaded_file($tmp, $dest);
}

// Negative 3: mime_content_type validation before move.
// ok: wp-arbitrary-file-upload
function handle_upload_safe_3() {
    $allowed_mime_types = ['image/jpeg', 'image/png'];
    $mime = mime_content_type($_FILES['file']['tmp_name']);
    if (!in_array($mime, $allowed_mime_types)) {
        wp_die('MIME type not allowed');
    }
    move_uploaded_file($_FILES['file']['tmp_name'], WP_CONTENT_DIR . '/uploads/file');
}
