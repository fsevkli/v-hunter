"""
pre_filter.py

Zero-LLM-cost pre-screening applied to every Semgrep candidate before
it reaches the LLM triager. Eliminates two large, predictable FP classes:

  1. Out-of-scope capability checks  — functions gated by manage_options /
     edit_pages / upload_files are Author/Editor/Admin-only and outside the
     Patchstack/WPScan scope we target (Subscriber/Contributor/Unauth).

  2. Nopriv-rule misfires — wp-nopriv-missing-nonce fires on every function
     that touches $_POST + a write sink, regardless of whether the function
     is actually registered as a wp_ajax_nopriv_ handler.  If the enclosing
     function name does not appear in any nopriv add_action() call across the
     whole plugin, the finding is auto-rejected.

Returns (verdict, reachability, reason) or None (→ proceed to LLM triage).
"""
import re
from pathlib import Path

from hunter.context import (
    _enclosing_function_name,
    _find_enclosing_function,
    _read_lines,
)

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Capabilities above Contributor level → out of scope for our bounty targets.
_OOS_CAP_RE = re.compile(
    r"current_user_can\s*\(\s*['\"]"
    r"(?:manage_options|administrator|"
    r"edit_users|promote_users|delete_users|create_users|"
    r"install_plugins|activate_plugins|update_plugins|delete_plugins|"
    r"install_themes|switch_themes|edit_themes|"
    r"import|export|"
    r"edit_pages|"      # Editor
    r"upload_files)"    # Author
    r"['\"]",
    re.IGNORECASE,
)

# Nonce verification — for the nopriv rule, presence means no CSRF
_NONCE_RE = re.compile(r"\b(?:check_ajax_referer|wp_verify_nonce)\s*\(")

# Nopriv hook prefixes (checked against the first quoted arg of add_action)
_NOPRIV_HOOK_PREFIXES = ("wp_ajax_nopriv_", "admin_post_nopriv_")

# Capabilities that imply admin/editor/author tier — out of scope for our
# bounty targets when used to gate a menu page or hook callback. Matched as
# a quoted string anywhere inside a registration STATEMENT (multi-line aware).
_ADMIN_CAP_NAMES = (
    "manage_options", "administrator",
    "edit_users", "promote_users", "delete_users", "create_users",
    "install_plugins", "activate_plugins", "update_plugins", "delete_plugins",
    "install_themes", "switch_themes", "edit_themes",
    "import", "export", "edit_pages", "upload_files",
    "manage_categories", "moderate_comments", "edit_others_posts",
    "edit_published_posts", "publish_pages", "edit_others_pages",
    "delete_pages", "delete_others_pages", "delete_published_pages",
)
_ADMIN_CAP_RE = re.compile(
    r"['\"](?:" + "|".join(_ADMIN_CAP_NAMES) + r")['\"]",
    re.IGNORECASE,
)

# Registration call names we walk multi-line to extract.
_REG_CALL_RE = re.compile(
    r"\b(add_action|add_menu_page|add_submenu_page|add_options_page|"
    r"add_management_page|add_dashboard_page|add_theme_page|"
    r"add_users_page|add_plugins_page|add_posts_page|add_pages_page|"
    r"add_media_page|add_comments_page|add_links_page)\s*\("
)

# Identifiers inside quoted strings — used to enumerate plausible callback
# names within a registration statement. Captures both:
#   'my_func'             → "my_func"
#   'MyClass::my_method'  → "MyClass" and "my_method"
_QUOTED_IDENT_RE = re.compile(r"['\"]([A-Za-z_]\w+)(?:::([A-Za-z_]\w+))?['\"]")

# Server-variable XSS: HTTP_HOST / SERVER_NAME require controlling the HTTP Host
# header, which load-balancers and web servers typically fix — not exploitable.
_SERVER_HOST_XSS_RE = re.compile(
    r"""\$_SERVER\s*\[\s*['"](?:SERVER_NAME|HTTP_HOST)['"]\s*\]""",
    re.IGNORECASE,
)

# DB-mediated deserialization: maybe_unserialize() on data fetched from the DB
# (get_comment_meta / get_post_meta / get_option / get_user_meta / get_transient).
# The attacker controls WHICH row to read, not WHAT is stored → FP.
_DB_GETTER_RE = re.compile(
    # WordPress-core getters
    r"\b(?:get_comment_meta|get_post_meta|get_option|get_user_meta"
    r"|get_site_option|get_transient|get_site_transient|get_metadata"
    r"|wp_get_attachment_metadata"
    # Raw $wpdb fetches — attacker controls WHICH row to read, not WHAT is stored
    r"|\$wpdb->get_row|\$wpdb->get_var|\$wpdb->get_col|\$wpdb->get_results"
    # Common ORM / data-store wrappers seen in WP plugins. Most plugins follow
    # the convention of *get*meta*, *get*option*, or *Data_Store::get*.
    r"|Data_Store::get_meta_value|Data_Store::get_option"
    r"|::get_meta_value|::get_meta|->get_meta_value|->get_meta"
    r")\s*\(",
    re.IGNORECASE,
)

# Numeric coercion sinks. Variables passed through these before being echoed
# cannot carry HTML payloads — XSS sinks downstream are defanged.
_NUMERIC_COERCE_RE = re.compile(
    r"\b(?:floatval|intval|absint|doubleval)\s*\("
    r"|\(\s*(?:int|integer|float|double|real)\s*\)",
    re.IGNORECASE,
)

# Nonce-verification functions — name → 0-indexed position of the action arg.
# check_ajax_referer($action, $field)        → arg 0
# check_admin_referer($action)               → arg 0
# wp_verify_nonce($nonce, $action)           → arg 1
# A regex-only extractor is too brittle here because PHP code routinely
# passes `$_POST['_wpnonce']` as the first arg, and the array-access key
# is itself a quoted string — naive matching captures the wrong literal.
# Callers should use `_handler_nonce_actions()` which parses arguments via
# `_extract_balanced_call` + `_split_call_args`.
_NONCE_VERIFY_ARG_INDEX = {
    "check_ajax_referer":   0,
    "check_admin_referer":  0,
    "wp_verify_nonce":      1,
}
_NONCE_VERIFY_CALL_RE = re.compile(
    r"\b(" + "|".join(_NONCE_VERIFY_ARG_INDEX) + r")\s*\("
)

# Admin-only WP action hooks. When a wp_create_nonce site's enclosing
# function is attached to one of these, the nonce is admin-context-only.
_ADMIN_ONLY_HOOKS = frozenset({
    "admin_enqueue_scripts",
    "admin_menu",
    "admin_init",
    "admin_head",
    "admin_footer",
    "admin_notices",
    "admin_print_scripts",
    "admin_print_styles",
    "admin_print_footer_scripts",
    "network_admin_menu",
    "network_admin_notices",
})

# Front-end signals — when present near a wp_create_nonce call, the nonce
# is potentially reachable by unauthenticated visitors, so it's NOT admin-only.
_FRONT_END_HOOK_RE = re.compile(
    r"add_action\s*\(\s*['\"]"
    r"(?:wp_enqueue_scripts|wp_footer|wp_head|template_redirect"
    r"|init|wp_loaded|template_include|wp_print_footer_scripts"
    r"|wp_print_scripts|wp_print_styles|the_content)"
    r"['\"]"
    r"|add_shortcode\s*\("
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _function_has_admin_oos_cap(
    func_text: str, plugin_path: Path
) -> tuple[str, str] | None:
    """Detect whether the enclosing function gates execution on an admin-tier
    capability (manage_options, edit_users, install_plugins, …).

    Returns (resolved_cap, source_kind) when found, where source_kind is one of:
      - 'literal'   — cap is a string literal (e.g. `current_user_can('manage_options')`)
      - 'variable'  — cap is a `$var` assigned to a literal somewhere in the function
      - 'constant'  — cap is a `BARE_CONSTANT` defined via `define()` in the plugin
      - 'custom_cap_admin_only' — cap is a plugin-defined custom cap that
        `add_cap()` only grants to administrator/super_admin

    Variable resolution is scoped to *func_text* (PHP locals don't escape the
    function), constant resolution is plugin-wide.

    Returns None when no admin-tier cap check is detected, or when the cap
    expression cannot be resolved to a literal (conservative: let LLM decide).
    """
    # Fast path: literal cap on a current_user_can() call. Covers >90% of
    # real plugins without paying the multi-line parse cost.
    fast = _OOS_CAP_RE.search(func_text)
    if fast:
        m = re.search(
            r"['\"](" + "|".join(_ADMIN_CAP_NAMES) + r")['\"]",
            fast.group(0),
            re.IGNORECASE,
        )
        if m:
            return (m.group(1).lower(), "literal")

    # Slow path: walk every cap-check call (current_user_can, user_can,
    # author_can, current_user_can_for_blog), extract the cap arg, resolve
    # variables and constants to literals, check admin tier.
    for cm in _CAP_CHECK_RE.finditer(func_text):
        open_paren = cm.end() - 1
        stmt = _extract_balanced_call(func_text, open_paren, max_chars=2000)
        if not stmt:
            continue
        args = _split_call_args(stmt)
        arg_idx = _CAP_CHECK_ARG_INDEX[cm.group(1)]
        if arg_idx >= len(args):
            continue
        cap_expr = args[arg_idx].strip()
        if not cap_expr:
            continue

        is_literal  = len(cap_expr) >= 2 and cap_expr[0] in ("'", '"')
        is_constant = bool(re.match(r"^[A-Z_][A-Z0-9_]*$", cap_expr))
        src_kind = (
            "literal"  if is_literal
            else "constant" if is_constant
            else "variable"
        )

        resolved = _resolve_to_literal(cap_expr, func_text, plugin_path)
        if not resolved:
            continue
        cap_lower = resolved.lower()
        if cap_lower in _ADMIN_CAP_SET:
            return (cap_lower, src_kind)
        # Custom plugin cap — check if `add_cap()` only grants it to administrator.
        # Caches per (plugin, cap) so repeated candidates with the same cap
        # don't rescan the tree.
        if _custom_cap_is_admin_only(plugin_path, resolved):
            return (cap_lower, "custom_cap_admin_only")

    return None


# Per-(plugin_path, cap_name) cache: True iff the cap is granted only to
# administrator/super_admin via `add_cap()` calls. None = couldn't determine.
_CUSTOM_CAP_ADMIN_ONLY: dict[tuple[str, str], bool] = {}

# Roles considered out-of-scope for Patchstack/WPScan bounties.
_ADMIN_TIER_ROLES = frozenset({"administrator", "super_admin"})
# Roles in our bug-bounty scope — if any of these get the cap, it's NOT admin-only.
_SCOPE_ROLES = frozenset({
    "subscriber", "customer", "contributor", "author",
    "editor", "shop_manager",  # technically out of scope but treated as non-admin tier
})


def _custom_cap_is_admin_only(plugin_path: Path, cap_name: str) -> bool:
    """True iff the plugin grants *cap_name* only to administrator/super_admin
    via `add_cap()` calls anywhere in the codebase.

    Recognizes three common assignment patterns:
      A. `$wp_roles->add_cap('administrator', 'cap_name')` — role+cap as literals
      B. `$role->add_cap('cap_name')` where `$role = get_role('xxx')` — resolves
         the role variable via local assignment in the same file.
      C. `foreach ($caps as $c) { $X->add_cap('administrator', $c); }` — heuristic:
         when the cap appears as a literal inside an `array(...)` literal in the
         same file AND an `add_cap('role', $var)` call exists, the loop assignment
         is attributed to that role.

    Conservative: returns False when no grants are found (would let the LLM
    decide), or when any in-scope role (subscriber/customer/contributor/...)
    appears to receive the cap.
    """
    if not cap_name:
        return False
    key = (str(plugin_path), cap_name)
    if key in _CUSTOM_CAP_ADMIN_ONLY:
        return _CUSTOM_CAP_ADMIN_ONLY[key]

    cap_q = re.escape(cap_name)
    grants: set[str] = set()

    pat_a = re.compile(
        r"->\s*add_cap\s*\(\s*['\"]([\w\-]+)['\"]\s*,\s*['\"]" + cap_q + r"['\"]"
    )
    pat_b_grant = re.compile(
        r"\$(\w+)\s*->\s*add_cap\s*\(\s*['\"]" + cap_q + r"['\"]"
    )
    pat_b_assign = re.compile(
        r"\$(\w+)\s*=\s*get_role\s*\(\s*['\"](\w+)['\"]"
    )
    pat_c_loop = re.compile(
        r"->\s*add_cap\s*\(\s*['\"]([\w\-]+)['\"]\s*,\s*\$\w+\s*\)"
    )
    pat_c_array = re.compile(
        r"array\s*\([^)]*['\"]" + cap_q + r"['\"]", re.DOTALL
    )

    for php_file in plugin_path.rglob("*.php"):
        try:
            text = php_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if cap_name not in text:
            continue

        # Pattern A: explicit role + cap literals
        for m in pat_a.finditer(text):
            grants.add(m.group(1).lower())

        # Pattern B: $role = get_role('x'); $role->add_cap('cap')
        role_vars: dict[str, str] = {}
        for m in pat_b_assign.finditer(text):
            role_vars[m.group(1)] = m.group(2).lower()
        for m in pat_b_grant.finditer(text):
            if m.group(1) in role_vars:
                grants.add(role_vars[m.group(1)])

        # Pattern C: foreach-loop assignment of an array containing the cap
        if pat_c_array.search(text):
            for m in pat_c_loop.finditer(text):
                grants.add(m.group(1).lower())

    if not grants:
        result = False
    elif grants & _SCOPE_ROLES:
        result = False
    else:
        result = grants <= _ADMIN_TIER_ROLES

    _CUSTOM_CAP_ADMIN_ONLY[key] = result
    return result


def _handler_nonce_actions(func_text: str) -> list[str]:
    """Extract every nonce action name verified by the handler (via
    check_ajax_referer / wp_verify_nonce / check_admin_referer).

    Parses each call via the balanced-call extractor so that array-access
    syntax in earlier arguments (e.g. `$_POST['_wpnonce']`) doesn't fool the
    regex — the key inside `[...]` is itself a quoted literal.

    Returns the actions in the order they appear; deduplicated.
    """
    seen: set[str] = set()
    actions: list[str] = []
    for cm in _NONCE_VERIFY_CALL_RE.finditer(func_text):
        open_paren = cm.end() - 1
        stmt = _extract_balanced_call(func_text, open_paren, max_chars=2000)
        if not stmt:
            continue
        args = _split_call_args(stmt)
        idx = _NONCE_VERIFY_ARG_INDEX[cm.group(1)]
        if idx >= len(args):
            continue
        action_expr = args[idx].strip().rstrip(",")
        # Only accept a string literal — variables/constants here are
        # rare and would need plugin-wide resolution; better to let LLM decide.
        if len(action_expr) >= 2 and action_expr[0] in ("'", '"') and action_expr[0] == action_expr[-1]:
            action = action_expr[1:-1]
            if action and action not in seen:
                seen.add(action)
                actions.append(action)
    return actions


# Per-(plugin_path, action) cache: True iff every wp_create_nonce(action) site
# is inside an admin-only code path. False if any front-end signal was seen,
# or if no creators were found at all.
_NONCE_ADMIN_ONLY: dict[tuple[str, str], bool] = {}


def _all_nonce_creators_admin_only(plugin_path: Path, nonce_action: str) -> bool:
    """True iff EVERY `wp_create_nonce('action')` site in the plugin is inside
    an admin-only code path (admin_enqueue_scripts, admin_menu, admin_init,
    or an admin-cap-gated function).

    Heuristic: for each call site, look at the surrounding ~4KB of source for
      - front-end action hooks / add_shortcode  → NOT admin-only (return False)
      - admin_enqueue_scripts / admin_menu hooks → admin-only signal
      - manage_options-class cap checks         → admin-only signal

    Returns False when no creators found at all (conservative — the nonce
    might be generated by JS or a partial-file refactor; let the LLM decide).
    """
    if not nonce_action:
        return False
    key = (str(plugin_path), nonce_action)
    if key in _NONCE_ADMIN_ONLY:
        return _NONCE_ADMIN_ONLY[key]

    action_q = re.escape(nonce_action)
    creator_re = re.compile(
        r"wp_create_nonce\s*\(\s*['\"]" + action_q + r"['\"]\s*\)"
    )
    admin_hook_re = re.compile(
        r"add_action\s*\(\s*['\"](?:" + "|".join(_ADMIN_ONLY_HOOKS) + r")['\"]"
    )

    found_any = False
    all_admin = True

    for php_file in plugin_path.rglob("*.php"):
        try:
            text = php_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if nonce_action not in text:
            continue
        for m in creator_re.finditer(text):
            found_any = True
            # Window: 4000 chars before, 200 after — captures the enclosing
            # function's add_action registration even in large files.
            lo = max(0, m.start() - 4000)
            hi = min(len(text), m.end() + 200)
            ctx = text[lo:hi]

            if _FRONT_END_HOOK_RE.search(ctx):
                all_admin = False
                break

            admin_signal = (
                bool(admin_hook_re.search(ctx))
                or "add_menu_page" in ctx
                or "add_submenu_page" in ctx
                or bool(_ADMIN_CAP_RE.search(ctx))
            )
            if not admin_signal:
                all_admin = False
                break
        if not all_admin:
            break

    result = found_any and all_admin
    _NONCE_ADMIN_ONLY[key] = result
    return result


def _xss_source_is_coerced(lines: list, line_start: int) -> bool:
    """For wp-reflected-xss rules: True if the variable being echoed/returned at
    *line_start* was assigned via numeric coercion (floatval / intval / absint /
    casts) within the preceding ~20 lines.

    Pattern: `$var = floatval($_POST['x']);  echo $var;`
    """
    if line_start < 1 or line_start > len(lines):
        return False
    flagged = lines[line_start - 1]
    m = re.search(
        r"(?:echo|print|return)\s+\$(\w+)|<\?=\s*\$(\w+)",
        flagged,
    )
    if not m:
        return False
    var = m.group(1) or m.group(2)
    if not var:
        return False
    lo = max(0, line_start - 20)
    ctx = "\n".join(lines[lo:line_start])
    assign_re = re.compile(
        r"\$" + re.escape(var) + r"\s*=\s*([^;]+);"
    )
    last = None
    for am in assign_re.finditer(ctx):
        last = am
    if not last:
        return False
    rhs = last.group(1)
    return bool(_NUMERIC_COERCE_RE.search(rhs))


# Per-(plugin_path, callback_name) cache: permission_callback function name
# registered alongside this callback in a register_rest_route(...) call.
# None means "no association found"; entries are stored on first lookup.
_REST_PERM_CALLBACK: dict[tuple[str, str], str | None] = {}


def _find_rest_permission_callback(plugin_path: Path, callback_name: str) -> str | None:
    """When *callback_name* is registered as a REST `callback`, return the
    function/method name of the sibling `permission_callback` declared in the
    same register_rest_route(...) args array.

    Recognizes the four common WordPress permission_callback forms:
      - `'permission_callback' => 'my_func'`
      - `'permission_callback' => 'MyClass::my_method'`
      - `'permission_callback' => [$this, 'my_method']`
      - `'permission_callback' => array($this, 'my_method')`

    Returns None when no association is found (conservative — let LLM decide).
    """
    if not callback_name:
        return None
    key = (str(plugin_path), callback_name)
    if key in _REST_PERM_CALLBACK:
        return _REST_PERM_CALLBACK[key]

    # Match every `'callback' => <value>` declaration, then check whether the
    # captured callback identifier matches *callback_name*. The four common
    # value forms each have their own alternation slot:
    #   'fn_name'                  → group 2
    #   'Cls::method'              → group 2 (last segment is the method)
    #   [<expr>, 'method']         → group 3
    #   array(<expr>, 'method')    → group 4
    cb_re = re.compile(
        r"['\"]callback['\"]\s*=>\s*(?:"
        r"['\"]([\w:]+)['\"]"
        r"|\[\s*[^,\[\]]+,\s*['\"](\w+)['\"]\s*\]"
        r"|array\s*\(\s*[^,()]+,\s*['\"](\w+)['\"]\s*\)"
        r")"
    )
    perm_re = re.compile(
        r"['\"]permission_callback['\"]\s*=>\s*(?:"
        r"['\"]([\w:]+)['\"]"
        r"|\[\s*[^,\[\]]+,\s*['\"](\w+)['\"]\s*\]"
        r"|array\s*\(\s*[^,()]+,\s*['\"](\w+)['\"]\s*\)"
        r")"
    )

    found: str | None = None
    for php_file in plugin_path.rglob("*.php"):
        try:
            text = php_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for cm in cb_re.finditer(text):
            cb_raw = cm.group(1) or cm.group(2) or cm.group(3)
            if not cb_raw:
                continue
            cb_short = cb_raw.split("::")[-1]
            if cb_short != callback_name:
                continue
            # Sibling permission_callback within ~500 chars (typical args-array span).
            window = text[cm.start():cm.start() + 500]
            pm = perm_re.search(window)
            if not pm:
                continue
            raw = pm.group(1) or pm.group(2) or pm.group(3)
            if raw:
                found = raw.split("::")[-1]
                break
        if found:
            break

    _REST_PERM_CALLBACK[key] = found
    return found


def _find_function_body(plugin_path: Path, func_name: str) -> str | None:
    """Locate `function <func_name>(...){ ... }` anywhere in the plugin tree
    and return the full source (signature through the matching `}`).

    Brace-matching skips string-literal contents to avoid early termination
    on `}` inside `"..."` / `'...'`. Comments and heredocs aren't masked
    (matches the existing context.py simplicity); the resulting body may
    therefore be a few chars long if the function contains heredoc-`}` —
    callers should treat None and non-string returns as "couldn't resolve".
    """
    if not func_name:
        return None
    sig_re = re.compile(r"\bfunction\s+" + re.escape(func_name) + r"\s*\(")
    for php_file in plugin_path.rglob("*.php"):
        try:
            text = php_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        m = sig_re.search(text)
        if not m:
            continue
        i = text.find("{", m.end())
        if i < 0:
            continue
        depth  = 1
        j      = i + 1
        L      = len(text)
        in_str = None
        while j < L and depth > 0:
            ch = text[j]
            if in_str is not None:
                if ch == "\\":
                    j += 2
                    continue
                if ch == in_str:
                    in_str = None
                j += 1
                continue
            if ch == "'" or ch == '"':
                in_str = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            j += 1
        return text[m.start():j]
    return None


def revalidate_candidate(plugin_path: Path, file_path: str, line_start: int) -> str | None:
    """Stale-line revalidator for the re-triage flow.

    The DB persists semgrep candidates by `(plugin_slug, file_path, line_start)`.
    When a plugin is updated upstream, those line numbers can drift or the
    file can be removed entirely. Call this before reprocessing an old
    candidate against a freshly-downloaded plugin source.

    Returns:
      - `None`               — file exists and has content at *line_start*;
                               candidate is still locatable.
      - `"file_missing"`     — `file_path` no longer exists in the plugin tree.
      - `"line_out_of_range"`— file exists but is shorter than *line_start*.

    Use the return value to mark the candidate as `stale_code` rather than
    pay LLM cost to triage a phantom finding.
    """
    cand_file = plugin_path / file_path
    if not cand_file.exists():
        return "file_missing"
    try:
        lines = _read_lines(cand_file)
    except OSError:
        return "file_missing"
    if not lines or line_start > len(lines):
        return "line_out_of_range"
    return None


def _enclosing_func_text(cand_file: Path, line_start: int) -> str:
    lines = _read_lines(cand_file)
    if not lines:
        return ""
    bounds = _find_enclosing_function(lines, line_start)
    if bounds:
        fs, fe = bounds
        return "\n".join(lines[fs - 1 : fe])
    lo = max(0, line_start - 100)
    hi = min(len(lines), line_start + 100)
    return "\n".join(lines[lo:hi])


def _has_server_host_xss(lines: list, line_start: int) -> bool:
    """True if the flagged XSS source is $_SERVER[SERVER_NAME/HTTP_HOST]."""
    lo = max(0, line_start - 10)
    hi = min(len(lines), line_start + 3)
    context = "\n".join(lines[lo:hi])
    return bool(_SERVER_HOST_XSS_RE.search(context))


def _is_db_mediated_deser(lines: list, line_start: int) -> bool:
    """True if maybe_unserialize on the flagged line is called on DB-stored data."""
    flagged = lines[line_start - 1] if line_start <= len(lines) else ""
    if "maybe_unserialize" not in flagged:
        return False
    # Look back up to 20 lines for a DB getter that assigned the value
    lo = max(0, line_start - 20)
    context = "\n".join(lines[lo:line_start])
    return bool(_DB_GETTER_RE.search(context))


# Per-plugin cache: list of (file, kind, statement_text, quoted_names_set)
# where `quoted_names_set` is every identifier found inside a quoted string
# in the statement. Built once per plugin path.
_PLUGIN_REG_STMTS: dict[str, list] = {}


def _extract_balanced_call(text: str, open_pos: int, max_chars: int = 4000) -> str:
    """Return the slice of *text* starting at *open_pos* (which must point at
    `(`) and ending just past the matching `)`. Skips parens inside string
    literals so `add_action('hook(', 'cb')` doesn't terminate early.

    Returns "" if the call is unbalanced within *max_chars*. The cap protects
    against pathological inputs without truncating real-world registration
    statements (the largest WP plugins use < 1000 chars per add_action).
    """
    if open_pos >= len(text) or text[open_pos] != "(":
        return ""

    depth   = 0
    i       = open_pos
    end     = min(len(text), open_pos + max_chars)
    in_str  = None  # active quote char, or None

    while i < end:
        ch = text[i]
        if in_str is not None:
            if ch == "\\":
                i += 2  # skip escape sequence
                continue
            if ch == in_str:
                in_str = None
            i += 1
            continue
        if ch == "'" or ch == '"':
            in_str = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_pos : i + 1]
        i += 1
    return ""


def _quoted_names_in(stmt: str) -> set[str]:
    """Return every identifier appearing inside a quoted string in *stmt*.
    Handles both bare callbacks (`'my_func'`) and Class::method form
    (`'MyClass::my_method'` → both `MyClass` and `my_method` are recorded)."""
    names: set[str] = set()
    for m in _QUOTED_IDENT_RE.finditer(stmt):
        names.add(m.group(1))
        if m.group(2):
            names.add(m.group(2))
    return names


def _build_reg_stmts(plugin_path: Path) -> list:
    """Build a per-plugin list of registration statements (multi-line aware).

    Each entry: (php_file, kind, statement_text, quoted_names).
    `kind` is the called function name (`add_action`, `add_menu_page`, ...).

    The cache is keyed by plugin path string so calling this repeatedly during
    pre-filtering of many candidates from the same plugin only walks the tree
    once.
    """
    key = str(plugin_path)
    if key in _PLUGIN_REG_STMTS:
        return _PLUGIN_REG_STMTS[key]

    stmts: list = []
    for php_file in plugin_path.rglob("*.php"):
        try:
            text = php_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _REG_CALL_RE.finditer(text):
            open_paren = m.end() - 1  # m.end() points just past `(`; back up one
            stmt = _extract_balanced_call(text, open_paren, max_chars=4000)
            if not stmt:
                continue
            kind = m.group(1)
            quoted = _quoted_names_in(stmt)
            stmts.append((php_file, kind, stmt, quoted))

    _PLUGIN_REG_STMTS[key] = stmts
    return stmts


def _registered_as_nopriv(plugin_path: Path, func_name: str) -> bool:
    """True if *func_name* is registered as a wp_ajax_nopriv_ or
    admin_post_nopriv_ handler anywhere in the plugin.

    Multi-line aware: parses each `add_action(...)` as a single statement, so
    the standard multi-line registration form is detected correctly.
    """
    for _php_file, kind, stmt, quoted in _build_reg_stmts(plugin_path):
        if kind != "add_action":
            continue
        if func_name not in quoted:
            continue
        # First quoted token in the statement is the hook name. Use a focused
        # match (after the opening paren) rather than `quoted` order, since
        # `quoted` is a set.
        hook_match = re.search(r"\(\s*['\"]([^'\"]+)['\"]", stmt)
        if hook_match and hook_match.group(1).startswith(_NOPRIV_HOOK_PREFIXES):
            return True
    return False


# 0-indexed position of the capability argument in each menu-registration call.
# Sourced from the WordPress function signatures.
_CAP_ARG_INDEX = {
    "add_menu_page":        2,
    "add_submenu_page":     3,  # parent_slug is arg 0
    "add_options_page":     2,
    "add_management_page":  2,
    "add_dashboard_page":   2,
    "add_theme_page":       2,
    "add_users_page":       2,
    "add_plugins_page":     2,
    "add_posts_page":       2,
    "add_pages_page":       2,
    "add_media_page":       2,
    "add_comments_page":    2,
    "add_links_page":       2,
}

_ADMIN_CAP_SET = frozenset(c.lower() for c in _ADMIN_CAP_NAMES)

# Capability-check functions and the 0-indexed position of their cap argument.
# Covers the four common WordPress cap-check entry points.
_CAP_CHECK_ARG_INDEX = {
    "current_user_can":          0,
    "user_can":                  1,  # arg 0 is the user
    "current_user_can_for_blog": 1,  # arg 0 is the blog id
    "author_can":                1,  # arg 0 is the post
}
_CAP_CHECK_RE = re.compile(
    r"\b(" + "|".join(_CAP_CHECK_ARG_INDEX) + r")\s*\("
)


def _split_call_args(stmt: str) -> list[str]:
    """Split the argument list inside `(arg1, arg2, ...)` into trimmed args.

    Respects nested parens/brackets and string literals — an arg containing
    a comma inside an array or string isn't over-split. Returns [] when
    *stmt* doesn't have the expected outer parens.
    """
    if len(stmt) < 2 or stmt[0] != "(" or stmt[-1] != ")":
        return []

    inner   = stmt[1:-1]
    args    : list[str] = []
    buf     : list[str] = []
    depth   = 0
    in_str  = None
    i       = 0
    L       = len(inner)

    while i < L:
        ch = inner[i]
        if in_str is not None:
            buf.append(ch)
            if ch == "\\" and i + 1 < L:
                buf.append(inner[i + 1])
                i += 2
                continue
            if ch == in_str:
                in_str = None
            i += 1
            continue
        if ch == "'" or ch == '"':
            in_str = ch
            buf.append(ch)
        elif ch in "([{":
            depth += 1
            buf.append(ch)
        elif ch in ")]}":
            depth -= 1
            buf.append(ch)
        elif ch == "," and depth == 0:
            args.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
        i += 1

    last = "".join(buf).strip()
    if last:
        args.append(last)
    return args


def _resolve_to_literal(
    expr: str,
    file_text: str,
    plugin_path: Path,
    depth: int = 0,
) -> str | None:
    """Resolve *expr* to a string literal value when possible.

    Handles three forms:
      - `'literal'` / `"literal"`  → returns the inner text
      - `$variable`                → searches *file_text* for the LAST
                                     `$variable = '...';` assignment
      - `BARE_CONSTANT`            → searches the plugin for
                                     `define('BARE_CONSTANT', '...')`

    Returns None when unresolvable. Recursion is bounded so a cyclic
    `$a = $b; $b = $a;` can't loop.
    """
    if depth > 3:
        return None

    e = expr.strip().rstrip(",")
    if not e:
        return None

    # 1. Literal string
    if len(e) >= 2 and e[0] == e[-1] and e[0] in ("'", '"'):
        return e[1:-1]

    # 2. Plain $variable (skip $this->prop, $a->b, $a::b — too ambiguous to
    #    resolve without proper PHP semantics)
    if e.startswith("$") and "->" not in e and "::" not in e:
        var_name = e[1:]
        if not re.match(r"^[A-Za-z_]\w*$", var_name):
            return None
        last_match = None
        for m in re.finditer(
            r"\$" + re.escape(var_name) + r"\s*=\s*([^;]+);",
            file_text,
        ):
            last_match = m
        if last_match:
            return _resolve_to_literal(
                last_match.group(1), file_text, plugin_path, depth + 1
            )
        return None

    # 3. Bare uppercase constant — search plugin-wide for define(...)
    if re.match(r"^[A-Z_][A-Z0-9_]*$", e):
        for php_file in plugin_path.rglob("*.php"):
            try:
                text = php_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            m = re.search(
                r"define\s*\(\s*['\"]" + re.escape(e) + r"['\"]\s*,\s*([^,)]+)",
                text,
            )
            if m:
                return _resolve_to_literal(m.group(1), text, plugin_path, depth + 1)
        return None

    return None


def _is_admin_menu_callback(plugin_path: Path, func_name: str) -> bool:
    """True if *func_name* is registered as a menu/submenu page callback with
    an admin-tier capability (manage_options, edit_users, install_plugins, ...).

    Multi-line aware. Recognizes the capability when it appears as:
      - a quoted string literal in the statement, OR
      - a `$variable` resolvable to a literal in the same file, OR
      - a `BARE_CONSTANT` resolvable via `define()` anywhere in the plugin.

    When the cap can't be resolved to a literal at all, the function returns
    False (no auto-reject — LLM triage decides).
    """
    for php_file, kind, stmt, quoted in _build_reg_stmts(plugin_path):
        if kind not in _CAP_ARG_INDEX:
            continue
        if func_name not in quoted:
            continue

        # Fast path: admin cap as a quoted literal anywhere in the statement.
        if _ADMIN_CAP_RE.search(stmt):
            return True

        # Slower path: parse args positionally and resolve the cap.
        args = _split_call_args(stmt)
        cap_idx = _CAP_ARG_INDEX[kind]
        if cap_idx >= len(args):
            continue
        try:
            file_text = php_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        resolved = _resolve_to_literal(args[cap_idx], file_text, plugin_path)
        if resolved and resolved.lower() in _ADMIN_CAP_SET:
            return True

    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run(
    plugin_path: Path,
    file_path: str,
    line_start: int,
    rule_id: str,
) -> tuple[str, str, str] | None:
    """
    Returns (verdict, reachability, reason) if the candidate can be auto-classified,
    or None to let the LLM triager handle it.

    verdict      : 'likely_fp' or 'real_but_not_cve_worthy'
    reachability : 'admin' or 'unknown'
    reason       : human-readable explanation (stored in triage.reasoning)
    """
    cand_file = plugin_path / file_path
    func_text = _enclosing_func_text(cand_file, line_start)
    if not func_text:
        return None

    lines     = _read_lines(cand_file)
    func_name = _enclosing_function_name(lines, line_start) if lines else None

    # ── Rule 1: Out-of-scope capability check (literal / variable / constant) ─
    oos = _function_has_admin_oos_cap(func_text, plugin_path)
    if oos:
        cap, kind = oos
        suffix = {
            "literal":  f"current_user_can('{cap}')",
            "variable": f"cap variable resolves to '{cap}'",
            "constant": f"cap constant resolves to '{cap}'",
        }[kind]
        return (
            "real_but_not_cve_worthy",
            "admin",
            f"[AUTO] {suffix} — requires Author+ access, out of scope for "
            f"current bug bounty targets",
        )

    # ── Rule 1b: Admin menu page callback ─────────────────────────────────
    if func_name and _is_admin_menu_callback(plugin_path, func_name):
        return (
            "real_but_not_cve_worthy",
            "admin",
            f"[AUTO] '{func_name}' is registered as an admin menu page callback "
            "(add_menu_page/add_submenu_page with manage_options) "
            "— only admins can reach this handler, out of scope",
        )

    # ── Rule 1c: REST permission_callback gates on admin-tier cap ─────────
    # When the flagged function is the `callback` for a register_rest_route,
    # check its sibling `permission_callback`. If that callback resolves to a
    # function whose body has an admin-tier cap check (manage_options or a
    # plugin-defined custom cap granted only to administrator), the route is
    # admin-only. Catches the FP family seen with checkoutwc-lite, legalblink,
    # ablocks, license-manager-for-woocommerce, etc.
    if func_name:
        perm_cb = _find_rest_permission_callback(plugin_path, func_name)
        if perm_cb:
            perm_body = _find_function_body(plugin_path, perm_cb)
            if perm_body and _function_has_admin_oos_cap(perm_body, plugin_path):
                return (
                    "real_but_not_cve_worthy",
                    "admin",
                    f"[AUTO] '{func_name}' is registered as a REST route callback; "
                    f"its sibling permission_callback '{perm_cb}' gates on an admin-tier "
                    "capability (current_user_can('manage_options') or equivalent custom cap) "
                    "— only admins can reach this route, out of scope",
                )

    # ── Rule 1c: Admin-only nonce reach ────────────────────────────────────
    # When the handler has no cap check but DOES verify a nonce, and every
    # wp_create_nonce site for that action is inside an admin-only code path,
    # the handler is effectively admin-only (subscribers can't obtain the nonce).
    # This catches the FP family observed in revisit (info-cards, ads-txt-by-magicbid,
    # customize-my-account, ymc-smart-filter, max-addons-for-bricks).
    if rule_id in (
        "wp-missing-cap-check",
        "wp-missing-cap-check-precise",
        "wp-missing-nonce-check",
        "wp-missing-nonce-check-precise",
        "wp-privesc-user-role",
    ):
        for action in _handler_nonce_actions(func_text):
            if _all_nonce_creators_admin_only(plugin_path, action):
                return (
                    "real_but_not_cve_worthy",
                    "admin",
                    f"[AUTO] handler verifies nonce '{action}', and every "
                    f"wp_create_nonce('{action}') site is inside an admin-only "
                    "code path (admin_enqueue_scripts / admin_menu / manage_options-gated) "
                    "— subscribers cannot obtain the nonce, so the handler is "
                    "effectively admin-only",
                )

    # ── Rule 3: Server-variable XSS (HTTP_HOST / SERVER_NAME) ─────────────
    if rule_id in ("wp-reflected-xss", "wp-reflected-xss-precise") and lines and _has_server_host_xss(lines, line_start):
        return (
            "likely_fp",
            "unknown",
            "[AUTO] XSS source is $_SERVER['SERVER_NAME'] or $_SERVER['HTTP_HOST'] "
            "— requires controlling the HTTP Host header, which load-balancers fix in production",
        )

    # ── Rule 3b: XSS source numerically coerced ────────────────────────────
    # `$x = floatval($_POST['p']); echo $x;` — the cast defangs HTML payloads.
    if rule_id in ("wp-reflected-xss", "wp-reflected-xss-precise") and lines and _xss_source_is_coerced(lines, line_start):
        return (
            "likely_fp",
            "unknown",
            "[AUTO] variable at XSS sink was assigned via numeric coercion "
            "(floatval/intval/absint/cast) before being echoed — payload is "
            "reduced to a number and cannot carry HTML",
        )

    # NOTE: DB-mediated POI auto-reject removed — `maybe_unserialize(get_option(...))`
    # is only a FP when the write path for that option is also protected; if a
    # low-privilege user can write arbitrary data to the option, the read-side
    # deserialization is a real POI chain. Let the LLM triager verify both sides.

    # ── Rule 2 (nopriv rule only) ──────────────────────────────────────────
    if rule_id == "wp-nopriv-missing-nonce":
        # 2a: Function not registered as a nopriv handler anywhere in plugin
        if func_name and not _registered_as_nopriv(plugin_path, func_name):
            return (
                "likely_fp",
                "unknown",
                f"[AUTO] '{func_name}' not found in any wp_ajax_nopriv_ / "
                f"admin_post_nopriv_ registration across the plugin",
            )

        # 2b: Nonce present in the handler — not a CSRF issue
        if _NONCE_RE.search(func_text):
            return (
                "likely_fp",
                "unknown",
                "[AUTO] nonce verification (check_ajax_referer / wp_verify_nonce) "
                "found inside the nopriv handler — request origin is validated",
            )

    return None  # Needs LLM triage
