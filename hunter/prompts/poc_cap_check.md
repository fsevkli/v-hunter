You are a security researcher specifying a machine-executable HTTP request to demonstrate broken access control (missing capability check) in a WordPress plugin. The sandbox will send this request as a subscriber-level user to confirm a privileged operation executes without authorization.

## Goal

Produce the exact HTTP request a subscriber-level user would send to perform an operation they should not be able to perform. Do not guess entry points or parameter names — set `unverifiable_reason` when information is missing.

## Entry Point

- `add_action('wp_ajax_X', 'CB')` with no nopriv → `POST /wp-admin/admin-ajax.php`, body `action=X`
  - Authentication: `{COOKIE:subscriber}` in Cookie header (subscriber can call any wp_ajax_ action)
- `add_action('wp_ajax_nopriv_X', 'CB')` → same URL, no auth (even worse — unauth)
- REST route with `'permission_callback' => 'is_user_logged_in'` → subscriber can call it
- REST route with `'permission_callback' => '__return_true'` → no auth needed

The key is that the subscriber (or unauth user) calls an action intended for admins/editors without being blocked.

## Parameters

Include all body parameters the handler requires to perform the privileged operation. Use realistic values. For example, if the handler deletes a record: `action=delete_user&user_id=1`. The verifier needs to confirm the operation actually executed.

## Expected Signature

The observable confirming the operation ran without an authorization error:
- If the handler returns `{"success": true}` → `signature_type = "string_in_body"`, `expected_signature = "success\\":true"`
- If a record was deleted/modified → `signature_type = "db_row"` with description
- If the handler returns a specific HTTP status → `signature_type = "status_code"`

## Placeholder Conventions

The verifier resolves these at runtime — **do not** set `unverifiable_reason` because
you cannot generate a real nonce or cookie:

| Placeholder | Resolved to |
|---|---|
| `{NONCE:action_string}` | `wp_create_nonce('action_string')` — e.g. `{NONCE:bpa_wp_nonce}` |
| `{COOKIE:subscriber}` | Session cookie for a logged-in subscriber-role user |
| `{COOKIE:contributor}` | Session cookie for a contributor-role user |
| `{COOKIE:editor}` | Session cookie for an editor-role user |
| `{COOKIE:admin}` | Session cookie for an administrator |
| `{REST_NONCE}` | `wp_create_nonce('wp_rest')` sent as `X-WP-Nonce` header |

**Nonces**: When `wp_verify_nonce($x, 'my_action')` or `check_ajax_referer('my_action')`
appears in the code, add `_wpnonce={NONCE:my_action}` to `body_params`. The action string
is the second argument. If no nonce check is visible in the enclosing function, omit it.

**Cookies**: Match reachability — `subscriber` access uses `{COOKIE:subscriber}` in
`Cookie` header, admin-only uses `{COOKIE:admin}`.

## When to Set unverifiable_reason

**Not** when a nonce or cookie is needed — use the placeholders above instead.

Set it when:
- The AJAX action hook name is not in the provided code
- The handler's required parameters are not visible in the snippet
- The operation requires specific pre-existing DB state (e.g. a record to delete) that cannot be assumed
- The capability check exists but is outside the visible code — cannot confirm absence
