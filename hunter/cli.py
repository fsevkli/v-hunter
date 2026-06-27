import click
from hunter.db import migrate


@click.group()
@click.version_option("0.1.0")
def cli():
    """WP-Hunter: WordPress plugin vulnerability discovery pipeline."""
    migrate()


@cli.command()
@click.option("--slugs", default=None, help="Comma-separated plugin slugs.")
@click.option("--filter", "filter_expr", default=None, help='e.g. "installs:1000-50000,updated:<24mo"')
@click.option("--limit", default=50, show_default=True, help="Max plugins to ingest when using --filter.")
def ingest(slugs, filter_expr, limit):
    """Pull plugin source code from WordPress.org SVN."""
    from hunter.ingestor import run_ingest
    run_ingest(slugs=slugs, filter_expr=filter_expr, limit=limit)


@cli.command()
@click.option("--plugin", required=True, help="Plugin slug to scan.")
@click.option("--limit-per-plugin", default=30, show_default=True,
              help="Max candidates inserted per plugin (highest severity first).")
def scan(plugin, limit_per_plugin):
    """Run Semgrep static filter on a plugin."""
    from hunter.static_filter import run_scan
    run_scan(plugin_slug=plugin, limit_per_plugin=limit_per_plugin)


@cli.command()
@click.option("--plugin", required=True, help="Plugin slug to triage.")
@click.option(
    "--engine",
    type=click.Choice(["haiku", "claude-code"]),
    default="haiku",
    show_default=True,
    help=(
        "Triage engine. 'haiku' uses the Anthropic API ($ per candidate, "
        "unattended, prompt-cached, with Sonnet escalation on uncertainty). "
        "'claude-code' shells out to `claude -p` "
        "(no marginal API cost, slower, uses your CC subscription)."
    ),
)
@click.option(
    "--concurrency",
    type=int,
    default=None,
    help=(
        "Workers running in parallel. Default: $HUNTER_TRIAGE_CONCURRENCY or 1. "
        "Haiku engine: 5-10 is a good range. claude-code engine: 2-3."
    ),
)
def triage(plugin, engine, concurrency):
    """LLM-triage Semgrep candidates for a plugin."""
    if engine == "claude-code":
        from hunter.cc_triager import run_triage_cc
        run_triage_cc(plugin_slug=plugin, concurrency=concurrency)
    else:
        from hunter.triager import run_triage
        run_triage(plugin_slug=plugin, concurrency=concurrency)


@cli.command()
@click.option("--plugin", required=True, help="Plugin slug to generate PoCs for.")
def poc(plugin):
    """Generate proof-of-concept scripts for confirmed findings."""
    from hunter.poc_generator import run_poc
    run_poc(plugin_slug=plugin)


@cli.command()
@click.option("--candidate-id", default=None, type=int, help="Single candidate ID to verify.")
@click.option("--plugin", default=None, help="Plugin slug: verify all ready PoCs (or use with --setup-only).")
@click.option("--all-ready", is_flag=True, help="Verify all ready PoCs across all plugins.")
@click.option("--setup-only", is_flag=True, help="Start sandbox, print fixture info, then tear down.")
@click.option("--source", default=None, help="Override plugin source path (with --setup-only).")
@click.option("--keep-running", is_flag=True, help="Leave sandbox running after the run.")
def verify(candidate_id, plugin, all_ready, setup_only, source, keep_running):
    """Run PoCs in the Docker sandbox and record results."""
    if setup_only:
        if not plugin:
            raise click.UsageError("--setup-only requires --plugin")
        from hunter.verifier import run_setup_only
        run_setup_only(plugin_slug=plugin, plugin_source=source, keep_running=keep_running)
    elif all_ready:
        from hunter.verifier import run_verify_all_ready
        run_verify_all_ready(keep_running=keep_running)
    elif plugin:
        from hunter.verifier import run_verify_plugin
        run_verify_plugin(plugin_slug=plugin, keep_running=keep_running)
    elif candidate_id is not None:
        from hunter.verifier import run_verify
        run_verify(candidate_id=candidate_id, keep_running=keep_running)
    else:
        raise click.UsageError(
            "provide one of: --candidate-id, --plugin, --all-ready, or --setup-only"
        )


@cli.command("review")
def review_queue():
    """Interactive human review queue for confirmed findings."""
    from hunter.review import run_review
    run_review()


@cli.command()
@click.option("--candidate-id", required=True, type=int, help="Candidate ID to build a report for.")
def report(candidate_id):
    """Generate a markdown vulnerability report."""
    from hunter.reporter import run_report
    run_report(candidate_id=candidate_id)


@cli.command()
@click.option("--plugin", required=True, help="Plugin slug to run through the full pipeline.")
@click.option(
    "--engine",
    type=click.Choice(["haiku", "claude-code"]),
    default="haiku",
    show_default=True,
    help="Triage engine — see `hunter triage --help`.",
)
def pipeline(plugin, engine):
    """Run all stages end-to-end for a plugin."""
    from hunter.ingestor import run_ingest
    from hunter.static_filter import run_scan
    from hunter.poc_generator import run_poc

    click.echo(f"[pipeline] Ingesting {plugin}...")
    run_ingest(slugs=plugin)

    click.echo(f"[pipeline] Scanning {plugin}...")
    run_scan(plugin_slug=plugin)

    click.echo(f"[pipeline] Triaging {plugin} (engine={engine})...")
    if engine == "claude-code":
        from hunter.cc_triager import run_triage_cc
        run_triage_cc(plugin_slug=plugin)
    else:
        from hunter.triager import run_triage
        run_triage(plugin_slug=plugin)

    click.echo(f"[pipeline] Generating PoCs for {plugin}...")
    run_poc(plugin_slug=plugin)

    click.echo("[pipeline] Done. Run 'hunter review' to approve findings.")


@cli.command()
@click.option("--funnel", is_flag=True, help="Show per-run funnel (raw → confirmed) across stages.")
@click.option("--plugin", default=None, help="Restrict --funnel to a single plugin slug.")
@click.option("--validate-against", default=None, type=click.Path(exists=True),
              help="Ground-truth JSON file: report precision/recall vs. confirmed verifications.")
def stats(funnel, plugin, validate_against):
    """Show cost, throughput, and hit-rate statistics."""
    from hunter.db import get_conn

    if validate_against:
        from hunter.runs import compare_to_ground_truth
        result = compare_to_ground_truth(validate_against)
        click.echo(f"Matched:    {result['matched']}")
        click.echo(f"Missed:     {result['missed']}")
        click.echo(f"Extra:      {result['extra']}")
        click.echo(f"Precision:  {result['precision']:.2%}")
        click.echo(f"Recall:     {result['recall']:.2%}")
        if result["missed_items"]:
            click.echo("\nMissed (in ground truth, not confirmed):")
            for slug, fp, ln in result["missed_items"][:20]:
                click.echo(f"  {slug}  {fp}:{ln}")
        return

    if funnel:
        from hunter.runs import funnel_totals
        t = funnel_totals(plugin_slug=plugin)
        scope = f" ({plugin})" if plugin else ""
        click.echo(f"Funnel{scope}:")
        click.echo(f"  raw semgrep findings:     {int(t['raw_findings']):>7}")
        click.echo(f"  -> pre-filter killed:      {int(t['pre_filter_killed']):>7}")
        click.echo(f"  -> inserted candidates:    {int(t['inserted_candidates']):>7}")
        click.echo(f"  -> LLM verdict real:       {int(t['llm_real']):>7}")
        click.echo(f"  -> LLM verdict fp/oos:     {int(t['llm_fp']):>7}")
        click.echo(f"  -> LLM needs context:      {int(t['llm_needs_context']):>7}")
        click.echo(f"  -> LLM escalated:          {int(t['llm_escalated']):>7}")
        click.echo(f"  -> PoCs generated:         {int(t['pocs_generated']):>7}")
        click.echo(f"  -> sandbox confirmed:      {int(t['sandbox_confirmed']):>7}")
        click.echo(f"  -> sandbox unverifiable:   {int(t['sandbox_unverifiable']):>7}")
        click.echo(f"\n  total cost:               ${t['cost_usd']:.4f}")
        return

    conn = get_conn()
    row = conn.execute(
        "SELECT COUNT(*) AS c, COALESCE(SUM(tokens_used),0) AS tok, COALESCE(SUM(cost_usd),0) AS usd FROM triage"
    ).fetchone()
    candidates = conn.execute("SELECT COUNT(*) AS c FROM candidates").fetchone()["c"]
    real = conn.execute("SELECT COUNT(*) AS c FROM triage WHERE verdict='real'").fetchone()["c"]
    confirmed = conn.execute("SELECT COUNT(*) AS c FROM verifications WHERE status='confirmed'").fetchone()["c"]

    click.echo(f"Candidates:       {candidates}")
    click.echo(f"Triaged:          {row['c']}")
    click.echo(f"Real findings:    {real}")
    click.echo(f"Confirmed in sandbox: {confirmed}")
    click.echo(f"Total tokens:     {row['tok']:,}")
    click.echo(f"Total cost:       ${row['usd']:.4f}")
