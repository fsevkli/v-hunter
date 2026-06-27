"""
Context expansion for PoC generation.

Augments the raw Semgrep snippet with:
  1. The enclosing PHP function (first+last 30 lines if > 80 lines)
  2. AJAX / REST / admin-page entry-point registrations
  3. Template-file parent-include references (when candidate is in a template dir)
  4. Nonce-verification calls in the candidate file (±5 lines each)

Cap: ~6 000 tokens (~24 000 chars) to keep prompt costs bounded.
"""
import re
from pathlib import Path

_MAX_CHARS = 24_000

_FUNC_DEF_RE = re.compile(r"\bfunction\s+(\w+)\s*\(")

_AJAX_RE = re.compile(
    r"add_action\s*\(\s*['\"]"
    r"(?:wp_ajax_nopriv_|wp_ajax_|admin_post_nopriv_|admin_post_)"
    r"[\w_-]+['\"]"
)
_REST_RE  = re.compile(r"register_rest_route\s*\(")
_MENU_RE  = re.compile(
    r"\badd_(?:menu_page|submenu_page|management_page|options_page|"
    r"dashboard_page|posts_page|media_page|links_page|pages_page|"
    r"comments_page|theme_page|plugins_page|users_page)\s*\("
)
_NONCE_RE = re.compile(r"\b(?:wp_verify_nonce|check_ajax_referer)\b")

# Directory names that indicate template / view files
_TEMPLATE_DIR_NAMES = {"tpls", "templates", "views", "partials", "template", "view", "partial"}


# ---------------------------------------------------------------------------
# PHP masking — required for robust brace counting
#
# Braces inside strings / comments / heredocs / nowdocs / HTML template chunks
# desynchronize naive `} - {` arithmetic. The masker replaces the contents of
# those regions with spaces, preserving newlines so line numbers remain
# correct after masking.
# ---------------------------------------------------------------------------

# Captures any of:
#   /* block comment */     (DOTALL — may span lines)
#   //  line comment
#   #   line comment
#   <<<TAG ... TAG[;]       heredoc (PHP 5.3+, indented closer allowed PHP 7.3+)
#   <<<'TAG' ... TAG[;]     nowdoc
#   "double quoted"         (may span lines per PHP semantics)
#   'single quoted'
_PHP_INNER_MASK_RE = re.compile(
    r"""(?xs)
      (/\* .*? \*/)                                # /* block */
    | (// [^\n]*)                                  # // line
    | (\# [^\n]*)                                  # #  line
    | (<<< [ \t]* ['"]? (?P<hd_label> \w+ ) ['"]?
        \n .*? \n [ \t]* (?P=hd_label) [ \t]* ;? ) # <<<TAG ... TAG;
    | ( "(?:\\.|[^"\\])*" )                        # "double quoted"
    | ( '(?:\\.|[^'\\])*' )                        # 'single quoted'
    """,
)


def _spaces_keeping_newlines(s: str) -> str:
    return "".join("\n" if c == "\n" else " " for c in s)


def _mask_php(text: str) -> str:
    """Replace PHP strings, comments, heredocs, nowdocs and inline-HTML chunks
    with spaces (newlines preserved). The output has the same length and line
    layout as *text*, but with brace-bearing content inside non-code regions
    blanked out — safe for brace counting and keyword scanning.
    """
    # Pass 1: inner constructs (strings, comments, heredocs, nowdocs).
    masked = _PHP_INNER_MASK_RE.sub(
        lambda m: _spaces_keeping_newlines(m.group(0)), text
    )

    # Pass 2: HTML between `?>` and the next `<?php` / `<?` (or EOF).
    masked = re.sub(
        r"(\?>)(.*?)(<\?(?:php\b|=)?|\Z)",
        lambda m: m.group(1) + _spaces_keeping_newlines(m.group(2)) + m.group(3),
        masked,
        flags=re.DOTALL,
    )

    # Pass 3: any HTML/text BEFORE the first PHP open tag (file starts in
    # template mode, then enters PHP).
    first_php = re.search(r"<\?(?:php\b|=)?", masked)
    if first_php and first_php.start() > 0:
        masked = (
            _spaces_keeping_newlines(masked[: first_php.start()])
            + masked[first_php.start():]
        )
    return masked


# Per-file cache of (start, end) 1-indexed function bounds. Forward-scan is
# O(file_size) and would otherwise repeat for every candidate in the same
# file. Key: (path string, content length, content first/last 64 chars) — a
# cheap fingerprint that invalidates on file edits within a single run.
_FILE_FUNCTIONS_CACHE: dict[tuple, list[tuple[int, int]]] = {}


def _scan_functions(text: str) -> list[tuple[int, int]]:
    """Forward-scan *text* (already masked or not — caller should mask first)
    for every named function declaration and its matching closing brace.

    Returns a list of (start_1indexed, end_1indexed) inclusive bounds, in the
    order encountered. Anonymous closures and arrow functions are excluded —
    `_FUNC_DEF_RE` requires `function NAME(...)`.
    """
    functions: list[tuple[int, int]] = []
    lines = text.splitlines()
    if not lines:
        return functions

    for i, line in enumerate(lines):
        for m in _FUNC_DEF_RE.finditer(line):
            depth = 0
            saw_open = False
            end_idx: int | None = None
            for j in range(i, len(lines)):
                jline = lines[j]
                start_pos = m.end() if j == i else 0
                for ch in jline[start_pos:]:
                    if ch == "{":
                        depth += 1
                        saw_open = True
                    elif ch == "}":
                        depth -= 1
                        if saw_open and depth == 0:
                            end_idx = j
                            break
                if end_idx is not None:
                    break
            if end_idx is not None:
                functions.append((i + 1, end_idx + 1))
    return functions


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_poc_context(plugin_path: str | Path, candidate: dict) -> str:
    """
    Return a multi-section context string for the PoC generator prompt.
    Replaces the bare code_snippet with richer context so the model can
    identify the AJAX action name, endpoint, and nonce requirements.
    """
    plugin_path = Path(plugin_path)
    file_rel    = candidate.get("file_path", "")
    line_start  = int(candidate.get("line_start") or 1)
    snippet     = candidate.get("code_snippet") or "(unavailable)"

    cand_file = plugin_path / file_rel
    sections: list[str] = []

    # 1. Semgrep snippet (always first)
    sections.append(f"### Semgrep Flagged Snippet\n\n```php\n{snippet}\n```")

    # 2. Full enclosing function
    sec = _enclosing_function_section(cand_file, line_start)
    if sec:
        sections.append(sec)

    # 3. Entry-point registrations (AJAX + REST + admin menu pages)
    sec = _registrations_section(plugin_path, cand_file, line_start)
    if sec:
        sections.append(sec)

    # 4. Template include references (only for template-directory files)
    if _is_template_file(cand_file):
        sec = _template_include_section(plugin_path, cand_file)
        if sec:
            sections.append(sec)

    # 5. Nonce / auth context
    sec = _nonce_section(cand_file)
    if sec:
        sections.append(sec)

    result = "\n\n".join(sections)
    if len(result) > _MAX_CHARS:
        result = result[:_MAX_CHARS] + "\n\n... [CONTEXT TRUNCATED] ..."
    return result


# ---------------------------------------------------------------------------
# Section: enclosing function
# ---------------------------------------------------------------------------

def _read_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def _enclosing_function_section(cand_file: Path, target_line: int) -> str:
    lines = _read_lines(cand_file)
    if not lines:
        return ""
    bounds = _find_enclosing_function(lines, target_line)
    if not bounds:
        return ""
    start, end = bounds
    func_lines = lines[start - 1 : end]
    n = len(func_lines)
    if n > 80:
        shown = (
            func_lines[:30]
            + [f"    // ... [TRUNCATED {n - 60} LINES] ..."]
            + func_lines[-30:]
        )
    else:
        shown = func_lines
    body = "\n".join(shown)
    return (
        f"### Enclosing Function"
        f" (lines {start}-{end} of {cand_file.name})\n\n```php\n{body}\n```"
    )


def _find_enclosing_function(lines: list[str], target_line: int) -> tuple[int, int] | None:
    """Return (start, end) 1-indexed inclusive line numbers of the named
    function whose body contains *target_line*, or None when no such function
    is found.

    Robust to braces inside strings / comments / heredocs / template HTML —
    the file is masked before brace counting. Uses a full forward pass and
    returns the INNERMOST containing function (correct for nested cases like
    methods within anonymous classes).
    """
    if not lines or target_line < 1:
        return None

    text = "\n".join(lines)
    fingerprint = (len(text), text[:64], text[-64:])
    functions = _FILE_FUNCTIONS_CACHE.get(fingerprint)
    if functions is None:
        functions = _scan_functions(_mask_php(text))
        _FILE_FUNCTIONS_CACHE[fingerprint] = functions

    containing = [(s, e) for s, e in functions if s <= target_line <= e]
    if not containing:
        return None
    return max(containing, key=lambda se: se[0])


def _enclosing_function_name(lines: list[str], target_line: int) -> str | None:
    """Name of the function whose body contains *target_line*, or None.

    Resolves via _find_enclosing_function so it inherits masking-aware
    scope detection. The name is then extracted from the function's actual
    declaration line — the function keyword and identifier are never inside
    a string or comment (the masker would have hidden them), so the original
    line is the correct source.
    """
    bounds = _find_enclosing_function(lines, target_line)
    if not bounds:
        return None
    start, _end = bounds
    if start - 1 >= len(lines):
        return None
    m = _FUNC_DEF_RE.search(lines[start - 1])
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# Section: entry-point registrations (AJAX + REST + admin menu pages)
# ---------------------------------------------------------------------------

# Per-process cache: str(plugin_path) → (ajax_regs, menu_regs)
# Avoids re-scanning the entire plugin for every candidate during triage.
_PLUGIN_REG_CACHE: dict[str, tuple] = {}


def _scan_plugin_registrations(
    plugin_path: Path,
) -> tuple[list, list]:
    """
    Scan plugin PHP files for AJAX/REST and admin menu registrations.
    Results are cached by plugin_path so the scan only runs once per plugin.
    Returns (ajax_regs, menu_regs) where each element is
    list[tuple[Path, int, str, str]] (file, lineno, stripped_line, kind).
    """
    key = str(plugin_path)
    if key in _PLUGIN_REG_CACHE:
        return _PLUGIN_REG_CACHE[key]

    ajax_regs: list[tuple[Path, int, str, str]] = []
    menu_regs: list[tuple[Path, int, str, str]] = []

    for php_file in sorted(plugin_path.rglob("*.php")):
        try:
            text = php_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if _AJAX_RE.search(line) or _REST_RE.search(line):
                ajax_regs.append((php_file, lineno, stripped, "ajax"))
            elif _MENU_RE.search(line):
                menu_regs.append((php_file, lineno, stripped, "menu"))

    _PLUGIN_REG_CACHE[key] = (ajax_regs, menu_regs)
    return ajax_regs, menu_regs


def _registrations_section(
    plugin_path: Path, cand_file: Path, target_line: int
) -> str:
    try:
        cand_text = cand_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""

    cand_lines     = cand_text.splitlines()
    enc_func       = _enclosing_function_name(cand_lines, target_line)
    all_cand_funcs = set(_FUNC_DEF_RE.findall(cand_text))

    ajax_regs, menu_regs = _scan_plugin_registrations(plugin_path)

    # Subset of ajax_regs originating from the candidate file
    cand_file_ajax = [(f, n, l, k) for f, n, l, k in ajax_regs if f == cand_file]

    # --- AJAX / REST relevance filtering (same logic as before) ---
    if enc_func:
        ajax_relevant = [(f, n, l, k) for f, n, l, k in ajax_regs if enc_func in l]
    else:
        ajax_relevant = []

    if not ajax_relevant:
        ajax_relevant = [
            (f, n, l, k) for f, n, l, k in ajax_regs
            if any(fname and fname in l for fname in all_cand_funcs)
        ]
    if not ajax_relevant:
        ajax_relevant = cand_file_ajax

    # --- Admin menu page relevance filtering ---
    # Priority 1: callback in registration references enclosing function or candidate functions
    if enc_func:
        menu_relevant = [(f, n, l, k) for f, n, l, k in menu_regs if enc_func in l]
    else:
        menu_relevant = []

    if not menu_relevant:
        menu_relevant = [
            (f, n, l, k) for f, n, l, k in menu_regs
            if any(fname and fname in l for fname in all_cand_funcs)
        ]
    # Fallback: include all menu page registrations (capped) — important for WP_List_Table cases
    if not menu_relevant:
        menu_relevant = menu_regs[:15]

    combined = ajax_relevant[:40] + menu_relevant[:20]
    if not combined:
        return ""

    lines_out: list[str] = []
    if ajax_relevant:
        lines_out.append("// --- AJAX / REST registrations ---")
        for php_file, lineno, line, _ in ajax_relevant[:40]:
            try:
                rel = php_file.relative_to(plugin_path)
            except ValueError:
                rel = Path(php_file.name)
            lines_out.append(f"// {rel}:{lineno}")
            lines_out.append(line)

    if menu_relevant:
        if lines_out:
            lines_out.append("")
        lines_out.append("// --- Admin menu page registrations ---")
        for php_file, lineno, line, _ in menu_relevant[:20]:
            try:
                rel = php_file.relative_to(plugin_path)
            except ValueError:
                rel = Path(php_file.name)
            lines_out.append(f"// {rel}:{lineno}")
            lines_out.append(line)

    body = "\n".join(lines_out)
    return f"### Entry-Point Registrations\n\n```php\n{body}\n```"


# ---------------------------------------------------------------------------
# Section: template include references
# ---------------------------------------------------------------------------

def _is_template_file(cand_file: Path) -> bool:
    """True if any parent path component is a template directory name."""
    return any(part.lower() in _TEMPLATE_DIR_NAMES for part in cand_file.parts[:-1])


def _template_include_section(plugin_path: Path, cand_file: Path) -> str:
    """Find plugin files that reference this template by its basename."""
    basename = cand_file.stem
    if not basename:
        return ""

    # Match the basename as a quoted string literal anywhere in PHP code
    pattern = re.compile(r"['\"]" + re.escape(basename) + r"['\"]")

    found: list[tuple[Path, int, int, list[str]]] = []
    for php_file in sorted(plugin_path.rglob("*.php")):
        if php_file == cand_file:
            continue
        try:
            lines = php_file.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            if pattern.search(line):
                lo = max(1, i - 10)
                hi = min(len(lines), i + 10)
                try:
                    rel = php_file.relative_to(plugin_path)
                except ValueError:
                    rel = Path(php_file.name)
                found.append((rel, lo, hi, lines[lo - 1 : hi]))
                break  # one match per file

    if not found:
        return ""

    snippets: list[str] = []
    for rel, lo, hi, chunk in found[:5]:
        snippets.append(f"// {rel}:{lo}-{hi}")
        snippets.extend(chunk)
        snippets.append("")

    body = "\n".join(snippets)
    return (
        f"### Template Include References for `{cand_file.name}`\n\n```php\n{body}\n```"
    )


# ---------------------------------------------------------------------------
# Section: nonce verification
# ---------------------------------------------------------------------------

def _nonce_section(cand_file: Path) -> str:
    lines = _read_lines(cand_file)
    if not lines:
        return ""

    snippets: list[str] = []
    covered:  set[int]  = set()

    for i, line in enumerate(lines, 1):
        if _NONCE_RE.search(line):
            lo = max(1, i - 5)
            hi = min(len(lines), i + 5)
            if lo not in covered:
                covered.update(range(lo, hi + 1))
                snippets.append(f"// lines {lo}-{hi}")
                snippets.extend(lines[lo - 1 : hi])
                snippets.append("")

    if not snippets:
        return ""

    body = "\n".join(snippets)
    return f"### Nonce / Auth Checks in {cand_file.name}\n\n```php\n{body}\n```"
