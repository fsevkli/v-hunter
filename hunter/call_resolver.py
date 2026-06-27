"""
Multi-function taint following — both directions.

Forward (callees):
    Given the flagged function body, find user-defined PHP functions called
    from it, recurse up to `max_depth` hops, and return their bodies. Catches
    sanitizers hidden behind wrapper helpers (`$this->sanitize_input(...)`,
    `Plugin_DB::escape(...)`) and multi-hop chains.

Backward (callers):
    Given the enclosing function name, find every callsite in the plugin and
    return each caller's body. Catches the inverse case: semgrep flags a sink
    inside a helper that takes a tainted parameter, and the actual taint
    source lives in the caller (e.g. `_do_delete($_POST['id'])`).

Design choices:
- Built-in/WP-core functions are excluded by a stop-list so we don't waste
  budget on calls whose definitions aren't in the plugin anyway.
- Function definitions AND callsites are indexed once per plugin path (cached)
  so triaging many candidates from the same plugin doesn't repeatedly walk
  the tree.
- Budget caps (max callees/callers, max lines per body) prevent runaway prompts.
- Caller-following skips functions with too many callsites (utility helpers)
  to avoid flooding the prompt with irrelevant context.
"""
import re
from pathlib import Path

# ---------------------------------------------------------------------------
# Stop-lists: things we never expand because they're built-ins or WP core
# ---------------------------------------------------------------------------

# Prefixes that almost always indicate WordPress core or PHP built-ins.
_STOPLIST_PREFIXES = (
    "esc_", "sanitize_", "wp_", "is_", "has_", "get_option", "get_user_meta",
    "get_post_meta", "get_term_meta", "get_comment_meta", "get_site_option",
    "get_transient", "get_site_transient", "update_option", "update_user_meta",
    "update_post_meta", "delete_option", "delete_transient", "add_option",
    "add_filter", "add_action", "remove_filter", "remove_action",
    "do_action", "apply_filters", "register_", "admin_url",
    "current_user_can", "current_user", "user_can",
    "str_", "strpos", "strstr", "strlen", "strtolower", "strtoupper",
    "substr", "preg_", "explode", "implode", "array_", "in_array",
    "json_", "serialize", "unserialize", "maybe_unserialize", "maybe_serialize",
    "file_", "fopen", "fwrite", "fread", "fclose", "fputs", "fgets",
    "intval", "floatval", "boolval", "strval", "settype", "gettype",
    "function_exists", "class_exists", "method_exists", "property_exists",
    "defined", "define", "constant",
    "header", "setcookie", "session_",
    "date", "time", "mktime", "strtotime", "gmdate", "microtime",
    "base64_", "md5", "sha1", "hash_", "crc32", "random_", "mt_rand", "rand",
    "uniqid", "openssl_", "password_",
    "trim", "ltrim", "rtrim", "ucfirst", "ucwords", "lcfirst",
    "sprintf", "printf", "vsprintf", "number_format",
    "htmlspecialchars", "htmlentities", "html_entity_decode",
    "urlencode", "urldecode", "rawurlencode", "rawurldecode",
    "parse_url", "http_build_query", "parse_str",
    "realpath", "dirname", "basename", "pathinfo",
    "mysqli_", "addslashes", "stripslashes",
    "check_ajax_referer", "check_admin_referer", "wp_verify_nonce", "wp_create_nonce",
    "load_plugin_textdomain", "plugin_dir_", "plugins_url",
)

# Exact matches (control-flow keywords, common globals, very common builtins)
_STOPLIST_EXACT = frozenset({
    "if", "else", "elseif", "while", "for", "foreach", "do", "switch", "case",
    "default", "break", "continue", "return", "yield", "try", "catch", "finally",
    "throw", "new", "class", "function", "interface", "trait", "extends",
    "implements", "use", "namespace", "include", "require", "include_once",
    "require_once", "true", "false", "null", "and", "or", "xor", "instanceof",
    "echo", "print", "die", "exit", "isset", "empty", "unset", "list", "array",
    "count", "sizeof", "min", "max", "abs", "round", "floor", "ceil", "pow", "sqrt",
    "self", "parent", "static", "this",
    "ob_start", "ob_end_clean", "ob_get_clean", "ob_get_contents", "ob_flush",
    "intval", "floatval", "boolval", "strval", "absint",
    "__", "_e", "_x", "_n", "esc_html__", "esc_attr__", "esc_html_e", "esc_attr_e",
})

# Match a function call. Captures method qualifier (optional) and function name.
# Won't match `function foo(` declarations (filtered post-hoc).
_CALL_RE = re.compile(
    r"""
    (?P<qualifier>
        \$this\s*->\s* |
        self\s*::\s* |
        static\s*::\s* |
        parent\s*::\s* |
        [A-Z][\w]*\s*::\s*
    )?
    (?P<name>[a-zA-Z_]\w*)
    \s*\(
    """,
    re.VERBOSE,
)

# Capture user-defined function/method declarations. Optional `&` for return-by-ref.
_FUNC_DEF_RE = re.compile(r"\bfunction\s+&?\s*([a-zA-Z_]\w*)\s*\(")

# Per-plugin function-definition index cache: {plugin_path_str: {name: [(file, line), ...]}}
_PLUGIN_FUNC_INDEX: dict[str, dict[str, list]] = {}

# Per-plugin callsite index cache: {plugin_path_str: {name: [(file, line), ...]}}
# Maps function name -> list of callsites across the plugin. Used by backward
# caller-following.
_PLUGIN_CALLSITE_INDEX: dict[str, dict[str, list]] = {}

# When the enclosing function has more than this many callsites it's almost
# certainly a generic utility — including all its callers would flood the
# prompt without adding signal. Skip caller-following in that case.
_MAX_CALLSITES_FOR_CALLER_TRACE = 40


def _is_stoplisted(name: str) -> bool:
    if name in _STOPLIST_EXACT:
        return True
    return name.startswith(_STOPLIST_PREFIXES)


def _strip_line_number_prefix(line: str) -> str:
    """The triager snippets are formatted as `NNNNN | source`. Strip that prefix."""
    if len(line) >= 8 and line[5:8] == " | ":
        return line[8:]
    return line


def _strip_strings_and_comments(line: str) -> str:
    """Remove single/double-quoted strings and `//` `#` comments from a line.

    Strings are replaced with '' so identifiers inside them don't get picked up
    as function calls. Block comments aren't handled (rare on a single line).
    """
    # Strings (greedy enough; we don't care about exact contents, just removal)
    line = re.sub(r"'(?:\\.|[^'\\])*'", "''", line)
    line = re.sub(r'"(?:\\.|[^"\\])*"', '""', line)
    # Single-line comments
    line = re.sub(r"//.*$", "", line)
    line = re.sub(r"#.*$", "", line)
    return line


def _extract_calls_from_snippet(snippet: str) -> list[str]:
    """Return ordered, deduplicated list of called-function names from *snippet*.

    Recognized:
    - Bare function calls: `foo(`
    - Recognized qualified calls: `$this->foo(`, `self::foo(`, `static::foo(`,
      `parent::foo(`, `ClassName::foo(`
    Ignored:
    - Generic `$obj->method(` — we can't know the runtime class, and a bare
      name match would risk collision with a same-named plugin function.
    - Generic `$obj::method(` — same reason.
    - Declarations (`function foo(...)`).
    """
    seen: set[str] = set()
    ordered: list[str] = []

    for raw_line in snippet.splitlines():
        line = _strip_line_number_prefix(raw_line)
        line = _strip_strings_and_comments(line)

        # Skip declarations entirely so we don't pick the function's own name.
        # Still scan the rest of the line for calls after the declaration
        # (rare: function foo() { return bar(); } on one line)
        if _FUNC_DEF_RE.search(line):
            line = _FUNC_DEF_RE.sub("", line, count=1)

        for m in _CALL_RE.finditer(line):
            name = m.group("name")
            if not name or name in seen:
                continue
            # If the call was preceded by `->` or `::` but the qualifier group
            # didn't capture (i.e. it was `$obj->name(` or `$obj::name(` rather
            # than `$this->`, `self::`, `static::`, `parent::`, `ClassName::`),
            # skip — we can't resolve the receiver's type from a snippet.
            if not m.group("qualifier"):
                ctx = line[max(0, m.start() - 2) : m.start()]
                if "->" in ctx or "::" in ctx:
                    continue
            if _is_stoplisted(name):
                continue
            # Skip uppercase-only constants like CONST(  — unlikely to be function defs
            if name.isupper() and len(name) > 1:
                continue
            seen.add(name)
            ordered.append(name)

    return ordered


def _build_plugin_index(plugin_path: Path) -> dict[str, list]:
    """Index user-defined functions/methods across the plugin (cached per path)."""
    key = str(plugin_path)
    if key in _PLUGIN_FUNC_INDEX:
        return _PLUGIN_FUNC_INDEX[key]

    index: dict[str, list] = {}
    for php_file in plugin_path.rglob("*.php"):
        try:
            text = php_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            stripped = _strip_strings_and_comments(line)
            for m in _FUNC_DEF_RE.finditer(stripped):
                name = m.group(1)
                index.setdefault(name, []).append((php_file, lineno))

    _PLUGIN_FUNC_INDEX[key] = index
    return index


def _extract_function_body(file_path: Path, def_line: int, max_lines: int) -> str:
    """Extract the function body whose `function` keyword is on *def_line*.

    Returns a numbered, fenced-code-ready string. Empty on read failure.
    """
    from hunter.context import _read_lines, _find_enclosing_function

    lines = _read_lines(file_path)
    if not lines:
        return ""

    # _find_enclosing_function walks back to find `function`. We pass a target
    # one line inside the body so it finds the def at def_line.
    target = def_line + 1 if def_line < len(lines) else def_line
    bounds = _find_enclosing_function(lines, target)
    if not bounds:
        return ""

    start, end = bounds
    body = lines[start - 1 : end]
    if len(body) > max_lines:
        body = body[:max_lines] + [f"    // ... [TRUNCATED {len(body) - max_lines} LINES] ..."]

    return "\n".join(f"{start + i:5d} | {line}" for i, line in enumerate(body))


def build_callees_section(
    plugin_path: Path,
    snippet: str,
    max_callees: int = 6,
    max_lines_per_callee: int = 60,
    exclude_self: str | None = None,
    max_depth: int = 2,
) -> str:
    """
    BFS-resolve user-defined functions called from *snippet*, recursively up to
    *max_depth* hops, and return their bodies as a single markdown section.

    Depth 1 means: functions directly invoked from the flagged snippet.
    Depth 2 means: functions invoked from those depth-1 callee bodies.
    Each deeper level uses a tighter budget to keep the prompt bounded.

    Parameters
    ----------
    exclude_self : if set, calls to this function name are skipped at every
                   depth (prevents the enclosing function from including its
                   own body when it appears as a callee of its own callees).
    max_depth    : 1 = direct callees only (legacy behaviour);
                   2 = also their callees;
                   3+ allowed but rarely useful — sanitizers typically live
                   within two hops.
    """
    if not snippet or max_depth < 1:
        return ""

    index = _build_plugin_index(plugin_path)
    if not index:
        return ""

    # Budget per depth: (cap_total_at_this_depth, max_lines_per_section).
    # Depth 1 gets the caller-supplied budget; each deeper level halves both
    # caps (with floors) so the prompt doesn't blow up on chatty plugins.
    depth_budget: dict[int, tuple[int, int]] = {
        1: (max_callees, max_lines_per_callee),
        2: (max(2, max_callees // 2), max(20, max_lines_per_callee // 2)),
        3: (2, 20),
    }

    sections: list[str] = []
    resolved: set[str] = set()
    if exclude_self:
        resolved.add(exclude_self)

    queue: list[tuple[int, str]] = [(1, snippet)]
    added_per_depth: dict[int, int] = {}

    while queue:
        depth, body_text = queue.pop(0)
        if depth > max_depth:
            continue
        cap, max_lines = depth_budget.get(depth, (2, 20))
        if added_per_depth.get(depth, 0) >= cap:
            continue

        for name in _extract_calls_from_snippet(body_text):
            if added_per_depth.get(depth, 0) >= cap:
                break
            if name in resolved:
                continue
            defs = index.get(name)
            if not defs:
                continue  # not user-defined (PHP/WP built-in or undefined)

            # Take the first definition; cross-class disambiguation is
            # intentionally not attempted here.
            file_path, lineno = defs[0]
            body = _extract_function_body(file_path, lineno, max_lines)
            if not body:
                continue

            try:
                rel = file_path.relative_to(plugin_path)
            except ValueError:
                rel = Path(file_path.name)

            depth_tag = "" if depth == 1 else f" (depth {depth})"
            sections.append(
                f"#### `{name}`{depth_tag} — defined at `{rel}:{lineno}`\n\n"
                f"```php\n{body}\n```"
            )
            resolved.add(name)
            added_per_depth[depth] = added_per_depth.get(depth, 0) + 1

            # Queue this body for further expansion at the next depth.
            if depth < max_depth:
                queue.append((depth + 1, body))

    if not sections:
        return ""

    header = (
        "### Called Functions (taint flow continues here)\n\n"
        "User-defined functions invoked from the flagged function body "
        "(depth 1) or from inside those callees (depth 2+). Check whether "
        "any of them sanitizes the tainted value before it reaches the sink.\n\n"
    )
    return header + "\n\n".join(sections)


# ---------------------------------------------------------------------------
# Backward caller-following
# ---------------------------------------------------------------------------

def _build_callsite_index(plugin_path: Path) -> dict[str, list]:
    """Index every callsite in the plugin by callee name (cached per path).

    Returns: {func_name: [(file_path, lineno), ...]}.

    Only callsites likely to be user-defined are recorded (stop-list filtered).
    Function declarations are explicitly skipped so the def line isn't
    miscounted as a caller of itself.
    """
    key = str(plugin_path)
    if key in _PLUGIN_CALLSITE_INDEX:
        return _PLUGIN_CALLSITE_INDEX[key]

    index: dict[str, list] = {}
    for php_file in plugin_path.rglob("*.php"):
        try:
            text = php_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            stripped = _strip_strings_and_comments(line)
            # Don't treat the declaration line itself as a callsite.
            if _FUNC_DEF_RE.search(stripped):
                stripped = _FUNC_DEF_RE.sub("", stripped, count=1)
            for m in _CALL_RE.finditer(stripped):
                name = m.group("name")
                if not name or _is_stoplisted(name):
                    continue
                if name.isupper() and len(name) > 1:
                    continue
                index.setdefault(name, []).append((php_file, lineno))

    _PLUGIN_CALLSITE_INDEX[key] = index
    return index


def _truncate_caller_body(
    body_lines: list[str], start: int, call_line: int, max_lines: int
) -> str:
    """Format a caller's function body for inclusion in the prompt.

    When the body fits within *max_lines*, return it whole.
    Otherwise, show:
      - The first ~40% of the budget (function head — where $_POST/$_GET sources
        typically appear)
      - A truncation marker
      - The remaining budget around the callsite line (±half) so the call to
        the flagged function stays visible in context.

    All output is line-numbered with the file's actual line numbers.
    """
    n = len(body_lines)
    if n <= max_lines:
        return "\n".join(f"{start + i:5d} | {ln}" for i, ln in enumerate(body_lines))

    head_n   = max(8, int(max_lines * 0.4))
    tail_n   = max_lines - head_n
    half     = max(4, tail_n // 2)
    call_idx = call_line - start  # 0-indexed offset within body_lines

    tail_lo = max(head_n, call_idx - half)
    tail_hi = min(n, tail_lo + tail_n)
    # Re-anchor lo if hi clamped at n
    tail_lo = max(head_n, tail_hi - tail_n)

    head_part = body_lines[:head_n]
    tail_part = body_lines[tail_lo:tail_hi]
    skipped   = tail_lo - head_n

    out: list[str] = []
    for i, ln in enumerate(head_part):
        out.append(f"{start + i:5d} | {ln}")
    if skipped > 0:
        out.append(f"      |     // ... [TRUNCATED {skipped} LINES] ...")
    for j, ln in enumerate(tail_part):
        out.append(f"{start + tail_lo + j:5d} | {ln}")
    return "\n".join(out)


def build_callers_section(
    plugin_path: Path,
    enclosing_func_name: str | None,
    max_callers: int = 4,
    max_lines_per_caller: int = 40,
) -> str:
    """
    Find functions across *plugin_path* that invoke *enclosing_func_name*, and
    return their bodies as a markdown section.

    Returns empty string when:
      - the enclosing function name is missing or stop-listed,
      - the name has no callsites (handler is hook-registered only, or it's
        used dynamically),
      - the name has more than _MAX_CALLSITES_FOR_CALLER_TRACE callsites
        (utility helper — would flood the prompt without signal).

    Each caller is shown by its enclosing-function body with the callsite
    line visible (truncated head+tail when the caller body is long).
    """
    if not enclosing_func_name:
        return ""
    if _is_stoplisted(enclosing_func_name):
        return ""
    if len(enclosing_func_name) < 3:
        return ""

    callsite_index = _build_callsite_index(plugin_path)
    callsites = callsite_index.get(enclosing_func_name, [])
    if not callsites:
        return ""
    if len(callsites) > _MAX_CALLSITES_FOR_CALLER_TRACE:
        return ""

    # Lazy imports to avoid circular deps (context.py imports from this module
    # in some downstream tooling).
    from hunter.context import (
        _read_lines,
        _find_enclosing_function,
        _enclosing_function_name,
    )

    sections: list[str] = []
    # Dedup by (file, caller_func_name) so multiple callsites within one caller
    # only contribute one section.
    seen: set[tuple[str, str]] = set()

    for file_path, call_line in callsites:
        if len(sections) >= max_callers:
            break

        lines = _read_lines(file_path)
        if not lines:
            continue

        caller_name = _enclosing_function_name(lines, call_line) or f"line_{call_line}"
        # Skip recursion (function calling itself).
        if caller_name == enclosing_func_name:
            continue

        dedup_key = (str(file_path), caller_name)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        bounds = _find_enclosing_function(lines, call_line)
        if bounds:
            start, end = bounds
            body_lines = lines[start - 1 : end]
            body_text  = _truncate_caller_body(
                body_lines, start, call_line, max_lines_per_caller
            )
        else:
            # No enclosing function (top-level call, e.g. inside a hook
            # registration block) — show ±10 lines of context.
            lo = max(0, call_line - 11)
            hi = min(len(lines), call_line + 10)
            body_text = "\n".join(
                f"{lo + i + 1:5d} | {ln}" for i, ln in enumerate(lines[lo:hi])
            )

        try:
            rel = file_path.relative_to(plugin_path)
        except ValueError:
            rel = Path(file_path.name)

        sections.append(
            f"#### called from `{caller_name}` — `{rel}:{call_line}`\n\n"
            f"```php\n{body_text}\n```"
        )

    if not sections:
        return ""

    header = (
        f"### Callers of `{enclosing_func_name}` (taint may originate here)\n\n"
        f"These functions invoke `{enclosing_func_name}` somewhere in their "
        f"body. The triager should check whether any caller passes user-"
        f"controlled input (e.g. `$_POST`, REST request params) into a "
        f"parameter that ultimately reaches the flagged sink.\n\n"
    )
    return header + "\n\n".join(sections)


def build_callers_section_for_candidate(
    candidate: dict,
    conn,
    max_callers: int = 4,
    max_lines_per_caller: int = 40,
) -> str:
    """Resolve plugin path + enclosing function from the candidate row, then
    delegate to build_callers_section."""
    slug = candidate.get("plugin_slug", "")
    row = conn.execute(
        "SELECT source_path FROM plugins WHERE slug = ?", (slug,)
    ).fetchone()
    if not row or not row["source_path"]:
        return ""

    plugin_path = Path(row["source_path"])
    if not plugin_path.exists():
        return ""

    from hunter.context import _read_lines, _enclosing_function_name

    cand_file = plugin_path / (candidate.get("file_path") or "")
    if not cand_file.exists():
        return ""

    lines = _read_lines(cand_file)
    if not lines:
        return ""

    enc_func = _enclosing_function_name(
        lines, int(candidate.get("line_start") or 1)
    )
    if not enc_func:
        return ""

    return build_callers_section(
        plugin_path,
        enc_func,
        max_callers=max_callers,
        max_lines_per_caller=max_lines_per_caller,
    )


def build_callees_section_for_candidate(
    candidate: dict,
    conn,
    max_callees: int = 6,
    max_lines_per_callee: int = 60,
) -> str:
    """Resolve plugin path from DB, then delegate to build_callees_section."""
    slug = candidate.get("plugin_slug", "")
    row = conn.execute(
        "SELECT source_path FROM plugins WHERE slug = ?", (slug,)
    ).fetchone()
    if not row or not row["source_path"]:
        return ""

    plugin_path = Path(row["source_path"])
    if not plugin_path.exists():
        return ""

    from hunter.context import _read_lines, _enclosing_function_name
    enc_func = None
    try:
        cand_file = plugin_path / (candidate.get("file_path") or "")
        if cand_file.exists():
            lines = _read_lines(cand_file)
            enc_func = _enclosing_function_name(
                lines, int(candidate.get("line_start") or 1)
            )
    except Exception:
        enc_func = None

    return build_callees_section(
        plugin_path,
        candidate.get("code_snippet") or "",
        max_callees=max_callees,
        max_lines_per_callee=max_lines_per_callee,
        exclude_self=enc_func,
    )
