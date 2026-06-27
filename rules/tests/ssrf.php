<?php
/**
 * Test fixtures for wp-ssrf (taint mode).
 * Annotations immediately before the sink line.
 *
 * Positives sourced from real CVE patterns:
 *   P1 — CVE-2022-0760 style (plugin fetches user-supplied URL via wp_remote_get)
 *   P2 — webhook endpoint posts to user-controlled URL
 *   P3 — curl_setopt with user-controlled CURLOPT_URL
 */

// ============================================================
// POSITIVES — must trigger wp-ssrf
// ============================================================

// Positive 1 (CVE-2022-0760 pattern): wp_remote_get with user-supplied URL.
$url = $_GET['url'];
// ruleid: wp-ssrf
$response = wp_remote_get($url);

// Positive 2: webhook posts to user-controlled endpoint.
$endpoint = $_POST['webhook_url'];
// ruleid: wp-ssrf
wp_remote_post($endpoint, ['body' => ['event' => 'test']]);

// Positive 3: curl with user-supplied URL via CURLOPT_URL.
$target = $_POST['target'];
$ch     = curl_init();
// ruleid: wp-ssrf
curl_setopt($ch, CURLOPT_URL, $target);

// ============================================================
// NEGATIVES — must NOT trigger wp-ssrf
// ============================================================

// Negative 1: wp_http_validate_url() validates the URL.
$raw_url       = $_GET['url'];
$validated_url = wp_http_validate_url($raw_url);
// ok: wp-ssrf
$resp          = wp_remote_get($validated_url);

// Negative 2: filter_var with FILTER_VALIDATE_URL.
$raw      = $_POST['feed_url'];
$safe_url = filter_var($raw, FILTER_VALIDATE_URL);
// ok: wp-ssrf
$feed     = wp_remote_get($safe_url);

// Negative 3: hardcoded URL — no user input involved.
// ok: wp-ssrf
$result = wp_remote_get('https://api.wordpress.org/plugins/info/1.2/');

// Negative 4: URL from trusted database source, not user superglobal.
$saved_url = get_option('my_api_endpoint');
// ok: wp-ssrf
$data      = wp_remote_get($saved_url);
