"""Preview the expanded context for the previously unverifiable candidates."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hunter.db import get_conn
from hunter.context import build_poc_context

conn = get_conn()

# Show context for the key bookingpress SQLi candidates (were unverifiable)
target_ids = [22, 15, 20, 86, 40]

for cid in target_ids:
    row = conn.execute("""
        SELECT c.*, pl.source_path
        FROM candidates c
        JOIN plugins pl ON pl.slug = c.plugin_slug
        WHERE c.id = ?
    """, (cid,)).fetchone()
    if not row:
        print(f"#{cid}: not found")
        continue

    candidate = dict(row)
    plugin_path = candidate.pop("source_path")
    ctx = build_poc_context(plugin_path, candidate)

    print(f"\n{'='*70}")
    print(f"Candidate #{cid}  {candidate['plugin_slug']}  {candidate['rule_id']}")
    print(f"File: {candidate['file_path']}:{candidate['line_start']}")
    print(f"Context length: {len(ctx)} chars")
    print("-"*70)

    # Show just the registration section
    if "### AJAX" in ctx:
        reg_start = ctx.index("### AJAX")
        reg_end   = ctx.index("\n\n###", reg_start) if "\n\n###" in ctx[reg_start+5:] else len(ctx)
        reg_end   = reg_start + ctx[reg_start:].index("\n\n###") if "\n\n###" in ctx[reg_start:] else len(ctx)
        print(ctx[reg_start:reg_end])
    else:
        print("  [no registration section found]")
