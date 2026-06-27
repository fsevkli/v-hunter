"""
Static filter: run Semgrep against an ingested plugin and write candidates to the DB.

Each Semgrep finding becomes one row in the `candidates` table.
`code_snippet` stores the complete enclosing function body (capped at 200 lines)
so the triager has full function-level context without line-window truncation.
`taint_trace` stores the Semgrep dataflow trace (source → intermediates → sink)
as a compact text block for direct injection into the LLM prompt.
"""
import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from hunter.db import get_conn

# ---------------------------------------------------------------------------
# Paths & constants
# ---------------------------------------------------------------------------

_PROJECT_ROOT = Path(__file__).parent.parent
RULES_DIR = _PROJECT_ROOT / "rules"

SEVERITY_RANK   = {"ERROR": 3, "WARNING": 2, "INFO": 1}
CONFIDENCE_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
CONTEXT_LINES   = 60    # fallback window when function extraction fails
MAX_FUNC_LINES  = 200   # cap for enclosing function extraction


# ---------------------------------------------------------------------------
# Semgrep discovery & invocation
# ---------------------------------------------------------------------------

def _find_semgrep() -> str:
    """Locate the semgrep binary: PATH first, then env override, then known fallbacks."""
    via_path = shutil.which("semgrep")
    if via_path:
        return via_path
    fallbacks = [
        os.environ.get("SEMGREP_BIN", ""),
        "/usr/local/bin/semgrep",
        "/usr/bin/semgrep",
    ]
    for f in fallbacks:
        if f and Path(f).exists():
            return f
    return "semgrep"


def _semgrep_env() -> dict:
    """Return os.environ copy that puts the Semgrep scripts dir on PATH so
    pysemgrep is findable as a sibling process."""
    env   = os.environ.copy()
    bindir = str(Path(_find_semgrep()).parent)
    if bindir and bindir not in env.get("PATH", ""):
        env["PATH"] = bindir + os.pathsep + env.get("PATH", "")
    return env


def _run_semgrep(plugin_path: Path, rules_dir: Path) -> list[dict]:
    """Invoke Semgrep and return the raw results list (empty on any error).

    Files are collected via rglob so semgrep doesn't fall back to
    `git ls-files` (which silently skips untracked plugin directories).
    On Windows, arguments are batched to stay under the CreateProcess limit.
    """
    php_files = [str(p) for p in plugin_path.rglob("*.php")]
    if not php_files:
        return []

    cmd_prefix = [
        _find_semgrep(),
        "--config", str(rules_dir),
        "--json",
        "--no-rewrite-rule-ids",
        "--quiet",
    ]
    prefix_chars = sum(len(a) + 1 for a in cmd_prefix)
    # Windows CreateProcess limit is ~32 767 chars; leave headroom for the prefix.
    max_file_chars = 28_000 - prefix_chars

    all_results: list[dict] = []

    batch: list[str] = []
    batch_chars = 0

    def _flush() -> None:
        if not batch:
            return
        result = subprocess.run(
            cmd_prefix + batch,
            capture_output=True,
            timeout=300,
            env=_semgrep_env(),
        )
        try:
            data = json.loads(result.stdout.decode("utf-8", errors="replace"))
            all_results.extend(data.get("results", []))
        except Exception:
            pass

    for fpath in php_files:
        flen = len(fpath) + 1  # +1 for the space separator
        if batch and batch_chars + flen > max_file_chars:
            _flush()
            batch, batch_chars = [], 0
        batch.append(fpath)
        batch_chars += flen

    _flush()
    return all_results


# ---------------------------------------------------------------------------
# Context extraction
# ---------------------------------------------------------------------------

def _read_context(file_path: Path, line_start: int, line_end: int,
                  context: int = CONTEXT_LINES) -> str:
    """Fallback: return a numbered ±context-line window around the finding."""
    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    lo = max(0, line_start - 1 - context)
    hi = min(len(lines), line_end + context)
    numbered = [f"{lo + i + 1:5d} | {line}" for i, line in enumerate(lines[lo:hi])]
    return "\n".join(numbered)


def _extract_enclosing_function(file_path: Path, line_start: int) -> str:
    """
    Extract the complete PHP function body that contains *line_start*.

    Delegates scope detection to hunter.context._find_enclosing_function,
    which:
      - masks PHP strings, comments, heredocs/nowdocs, and template-HTML
        chunks before brace counting (so a `}` inside a heredoc or block
        comment can't desynchronize the depth tracker),
      - does a full forward scan and picks the innermost function whose
        bounds contain the target line (handles nested classes / methods
        correctly).

    On failure, falls back to _read_context (±60 line window).
    Output format is identical: numbered lines `"NNNNN | source"`.
    """
    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return _read_context(file_path, line_start, line_start)

    from hunter.context import _find_enclosing_function

    bounds = _find_enclosing_function(lines, line_start)
    if not bounds:
        return _read_context(file_path, line_start, line_start)

    start_1, end_1 = bounds  # 1-indexed inclusive

    # Apply MAX_FUNC_LINES cap (preserves the prompt budget guarantee).
    if end_1 - start_1 > MAX_FUNC_LINES:
        end_1 = start_1 + MAX_FUNC_LINES

    body_lines = lines[start_1 - 1 : end_1]
    numbered = [
        f"{start_1 + i:5d} | {line}"
        for i, line in enumerate(body_lines)
    ]
    return "\n".join(numbered)


def _extract_taint_trace(finding: dict) -> str:
    """
    Format Semgrep's dataflow_trace (taint source → intermediates → sink)
    into a compact, LLM-readable string.

    Returns an empty string when no trace is available (pattern-mode rules,
    or Semgrep OSS without Pro taint tracing).
    """
    trace = finding.get("extra", {}).get("dataflow_trace", {})
    if not trace:
        return ""

    parts: list[str] = []

    def _loc(item: dict) -> str:
        loc = item.get("location", {})
        start = loc.get("start", {})
        return f"line {start.get('line', '?')}"

    def _content(item: dict) -> str:
        return item.get("content", "").strip()

    # Semgrep returns lists for each field
    sources = trace.get("taint_source") or []
    if isinstance(sources, dict):
        sources = [sources]
    for s in sources:
        parts.append(f"SOURCE ({_loc(s)}): {_content(s)}")

    intermediates = trace.get("intermediate_vars") or []
    if isinstance(intermediates, dict):
        intermediates = [intermediates]
    for step in intermediates:
        parts.append(f"  THROUGH ({_loc(step)}): {_content(step)}")

    sinks = trace.get("taint_sink") or []
    if isinstance(sinks, dict):
        sinks = [sinks]
    for s in sinks:
        parts.append(f"SINK ({_loc(s)}): {_content(s)}")

    return "\n".join(parts) if parts else ""


# ---------------------------------------------------------------------------
# Sorting / deduplication helpers
# ---------------------------------------------------------------------------

def _sort_key(finding: dict) -> tuple:
    """Higher severity and confidence sorts first (for limit selection)."""
    extra = finding.get("extra", {})
    sev   = SEVERITY_RANK.get(extra.get("severity", ""), 0)
    conf  = CONFIDENCE_RANK.get(extra.get("metadata", {}).get("confidence", ""), 0)
    return (-sev, -conf)


def _existing_keys(conn, slug: str) -> set[tuple]:
    rows = conn.execute(
        "SELECT rule_id, file_path, line_start, line_end "
        "FROM candidates WHERE plugin_slug = ?",
        (slug,),
    ).fetchall()
    return {
        (slug, r["rule_id"], r["file_path"], r["line_start"], r["line_end"])
        for r in rows
    }


# Rules that fire on overlapping code — deduplicate by location so the same
# sink isn't sent to the LLM twice under different rule IDs.
#
# Rule names are compared after stripping the '-precise' suffix (see
# _norm_rule), so a group entry like 'wp-missing-nonce-check' covers both the
# original and the -precise variant.
_DEDUP_GROUPS: list[frozenset[str]] = [
    frozenset({"wp-missing-nonce-check", "wp-nopriv-missing-nonce"}),
]


def _norm_rule(rule_id: str) -> str:
    """Strip the trailing '-precise' suffix and any 'rules.' namespace prefix
    so dedup-group membership can be checked against the bare rule name.

    semgrep emits check_ids like 'rules.wp-missing-nonce-check-precise'; the
    dedup groups list the canonical short names without the suffix.
    """
    name = rule_id.rsplit(".", 1)[-1]
    if name.endswith("-precise"):
        name = name[: -len("-precise")]
    return name


def _is_in_same_dedup_group(rule_a: str, rule_b: str) -> bool:
    """True iff *rule_a* and *rule_b* (after normalization) belong to a common
    dedup group — meaning one finding subsumes the other and only one needs to
    reach the LLM."""
    a, b = _norm_rule(rule_a), _norm_rule(rule_b)
    if a == b:
        return False  # same rule — handled by exact-key dedup, not this layer
    return any(a in g and b in g for g in _DEDUP_GROUPS)


def _location_key(slug: str, file_path: str, line_start: int) -> tuple:
    """Loose cross-rule dedup key: same sink line in the same file under the
    same plugin. Intentionally ignores line_end because sibling rules disagree
    on how far the dataflow extends (one reports only the sink line, another
    the whole source-to-sink range) — keying on line_end alone would miss real
    duplicates."""
    return (slug, file_path, line_start)


def _existing_locations(conn, slug: str) -> dict[tuple, str]:
    """Return {(slug, file, line_start): first_inserted_rule_id} for cross-rule
    dedup. When multiple rules already fired on the same line, the earliest
    insertion (lowest rowid) wins — matches the in-loop dedup order, where
    the first-seen finding on a line blocks later ones."""
    rows = conn.execute(
        "SELECT rule_id, file_path, line_start "
        "FROM candidates WHERE plugin_slug = ? ORDER BY id ASC",
        (slug,),
    ).fetchall()
    out: dict[tuple, str] = {}
    for r in rows:
        k = (slug, r["file_path"], r["line_start"])
        out.setdefault(k, r["rule_id"])
    return out


def _ensure_plugin_row(conn, slug: str, source_path: Path) -> None:
    """Upsert a minimal plugins row so the FK on candidates is satisfied
    even when run_scan is called without a prior ingest."""
    conn.execute(
        """INSERT INTO plugins
               (slug, name, version, active_installs, last_updated,
                source_path, ingested_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(slug) DO UPDATE SET
               source_path = excluded.source_path""",
        (slug, slug, "unknown", 0, "", str(source_path),
         datetime.now(timezone.utc).isoformat()),
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_scan(
    plugin_slug: str,
    plugin_path: Path | None = None,
    db_path: str | None = None,
    rules_dir: Path | None = None,
    limit_per_plugin: int = 30,
) -> int:
    """
    Scan *plugin_slug* with all Semgrep rules and write new findings to the DB.

    Parameters
    ----------
    plugin_slug       : slug that matches ``plugins.slug`` (used as FK)
    plugin_path       : explicit path to plugin source; resolved from DB or
                        ``plugins/{slug}/`` when omitted
    db_path           : override database file (useful in tests)
    rules_dir         : override rules directory (useful in tests)
    limit_per_plugin  : max candidates inserted; highest-severity/confidence first

    Returns
    -------
    Number of new rows inserted into ``candidates``.
    """
    import click

    conn           = get_conn(db_path)
    effective_rules = rules_dir or RULES_DIR

    # ---- Resolve plugin source path ----------------------------------------
    if plugin_path is None:
        row = conn.execute(
            "SELECT source_path FROM plugins WHERE slug = ?", (plugin_slug,)
        ).fetchone()
        plugin_path = (
            Path(row["source_path"]) if row else Path("plugins") / plugin_slug
        )

    if not plugin_path.exists():
        click.echo(f"[scan] plugin path not found: {plugin_path}")
        return 0

    # Ensure a plugins row exists so the FK constraint is satisfied
    _ensure_plugin_row(conn, plugin_slug, plugin_path)
    conn.commit()

    click.echo(f"[scan] {plugin_slug} @ {plugin_path}")

    # ---- Run Semgrep --------------------------------------------------------
    from hunter.runs import Run
    scan_run = Run("scan", plugin_slug=plugin_slug, db_path=db_path)
    scan_run.__enter__()

    findings = _run_semgrep(plugin_path, effective_rules)
    click.echo(f"[scan] {len(findings)} raw findings before dedup/limit")
    scan_run.bump("raw_findings", len(findings))

    # Highest severity + confidence first so the limit keeps the best findings
    findings.sort(key=_sort_key)

    # ---- Dedup + insert -----------------------------------------------------
    existing   = _existing_keys(conn, plugin_slug)
    locations  = _existing_locations(conn, plugin_slug)
    now        = datetime.now(timezone.utc).isoformat()
    inserted   = 0

    for f in findings:
        if inserted >= limit_per_plugin:
            break

        rule_id    = f.get("check_id", "")
        abs_path   = f.get("path", "")
        line_start = f["start"]["line"]
        line_end   = f["end"]["line"]
        severity   = f.get("extra", {}).get("severity", "")

        # Store relative path so DB rows survive directory moves
        try:
            rel_path = str(Path(abs_path).relative_to(plugin_path))
        except ValueError:
            rel_path = abs_path

        # Cross-rule dedup: a sibling rule in the same _DEDUP_GROUPS entry
        # already fired on this exact sink line. Skip; one finding is enough.
        loc_key = _location_key(plugin_slug, rel_path, line_start)
        existing_rule = locations.get(loc_key)
        if existing_rule and _is_in_same_dedup_group(rule_id, existing_rule):
            click.echo(
                f"  [dedup] {rule_id} @ {rel_path}:{line_start} "
                f"already covered by {existing_rule} — skipping"
            )
            continue

        # Same-rule dedup: protects against re-scanning an already-indexed
        # plugin. The exact (rule, file, start, end) key is correct here
        # because the same rule on the same range is a true duplicate.
        key = (plugin_slug, rule_id, rel_path, line_start, line_end)
        if key in existing:
            continue

        # Extract full enclosing function body (better than ±N-line window)
        snippet = _extract_enclosing_function(Path(abs_path), line_start)
        if not snippet:
            snippet = _read_context(Path(abs_path), line_start, line_end)

        # Extract Semgrep's taint dataflow trace when available
        taint_trace = _extract_taint_trace(f)

        conn.execute(
            """INSERT INTO candidates
                   (plugin_slug, rule_id, file_path, line_start, line_end,
                    code_snippet, taint_trace, semgrep_severity, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (plugin_slug, rule_id, rel_path, line_start, line_end,
             snippet, taint_trace, severity, now),
        )
        # Get the new candidate's ID for possible pre-triage
        cid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        existing.add(key)
        # Update the in-memory location map so a sibling rule firing on this
        # same line LATER in the current scan is dedup'd (was missing — the
        # original code only loaded `locations` from the DB once and never
        # refreshed it, so intra-scan dedup never triggered).
        locations.setdefault(loc_key, rule_id)
        inserted += 1

        # Pre-filter: auto-triage obvious FPs/OOS at zero LLM cost
        try:
            from hunter.pre_filter import run as pre_filter
            result = pre_filter(plugin_path, rel_path, line_start, rule_id)
            if result:
                verdict, reachability, reason = result
                conn.execute(
                    """INSERT OR IGNORE INTO triage
                           (candidate_id, verdict, reachability, reasoning, poc_outline,
                            confidence, tokens_used, cost_usd, triaged_at)
                       VALUES (?, ?, ?, ?, '', 'high', 0, 0.0, ?)""",
                    (cid, verdict, reachability, reason, now),
                )
                scan_run.bump("pre_filter_killed")
                click.echo(
                    f"  [pre-filter] {rule_id} => {verdict} ({reason[:60]}...)"
                )
        except Exception:
            pass  # pre-filter failure must never break the scan

    scan_run.bump("inserted_candidates", inserted)
    # Commit the outer scan connection BEFORE the Run UPDATE so they don't
    # race for the SQLite writer lock (Run.__exit__ opens its own conn).
    conn.commit()
    scan_run.__exit__(None, None, None)
    click.echo(f"[scan] {inserted} new candidates written")
    return inserted
