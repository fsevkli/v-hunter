#!/bin/bash
# Auto-hunt v2: tighter danger patterns, longer chain.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

LOG=scripts/auto_hunt_v2_log.txt
FLAGS=scripts/auto_hunt_v2_flags.txt
ITERATIONS=${1:-20}

> "$LOG"
> "$FLAGS"
echo "=== Auto-hunt v2 started at $(date) ===" >> "$LOG"

for i in $(seq 1 $ITERATIONS); do
    echo "" >> "$LOG"
    echo "=== Iteration $i ===" >> "$LOG"

    python scripts/discover_targets.py --limit 5 >> "$LOG" 2>&1

    [ ! -d plugins ] && continue

    for plugin_dir in plugins/*/; do
        slug=$(basename "$plugin_dir")

        # Tighter danger patterns - looking for state mutation w/o proper guards
        # Pattern 1: nopriv handler with wp_insert_user (account creation)
        # Pattern 2: update_user_meta with $_POST key (mass assignment)
        # Pattern 3: update_option with $_POST/REQUEST value (option overwrite)
        # Pattern 4: unlink/file_get_contents with user input (path traversal)
        # Pattern 5: $wpdb->query/get_results with $_POST interpolation (SQLi w/o prepare)

        d1=$(grep -rEn "wp_insert_user\s*\(\s*[\$\(]" "$plugin_dir" 2>/dev/null | grep -v vendor | grep -v "wp-async" | head -5)
        d2=$(grep -rEn "update_user_meta\s*\(.*\\\$_(POST|REQUEST|GET)\[.+\]\s*,\s*\\\$_(POST|REQUEST|GET)" "$plugin_dir" 2>/dev/null | grep -v vendor | head -5)
        d3=$(grep -rEn "update_option\s*\(\s*\\\$_(POST|REQUEST|GET)" "$plugin_dir" 2>/dev/null | grep -v vendor | head -5)
        d4=$(grep -rEn "unlink\s*\(\s*[^)]*\\\$_(POST|REQUEST|GET)" "$plugin_dir" 2>/dev/null | grep -v vendor | head -5)
        d5=$(grep -rEn "wpdb->(query|get_results|get_var|get_row)\s*\(\s*[\"']\s*[A-Z][^%]*\\\$_(POST|REQUEST|GET)" "$plugin_dir" 2>/dev/null | grep -v vendor | head -5)
        # Pattern 6: nopriv handlers that call wp_handle_upload
        d6=$(grep -rEn "wp_handle_upload\s*\(\s*\\\$_FILES" "$plugin_dir" 2>/dev/null | grep -v vendor | head -3)
        # Pattern 7: missing nonce w/ state mutation - find nopriv handlers without check_ajax_referer
        # (skip for now - too noisy)

        installs=$(curl -s "https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&slug=$slug" | python -c "import json,sys; print(json.load(sys.stdin).get('active_installs', 0))" 2>/dev/null)
        echo "[$slug] installs=$installs" >> "$LOG"

        # Flag if any danger pattern matches
        anyflag=""
        [ -n "$d1" ] && anyflag="${anyflag}P1_INSERT_USER "
        [ -n "$d2" ] && anyflag="${anyflag}P2_USER_META "
        [ -n "$d3" ] && anyflag="${anyflag}P3_UPDATE_OPTION "
        [ -n "$d4" ] && anyflag="${anyflag}P4_UNLINK "
        [ -n "$d5" ] && anyflag="${anyflag}P5_SQLI "
        [ -n "$d6" ] && anyflag="${anyflag}P6_FILE_UPLOAD "

        if [ -n "$anyflag" ]; then
            echo "[FLAG][iter=$i][installs=$installs][$anyflag] $slug" >> "$FLAGS"
            for d in "$d1" "$d2" "$d3" "$d4" "$d5" "$d6"; do
                [ -n "$d" ] && echo "$d" >> "$FLAGS"
            done
            echo "---" >> "$FLAGS"
        fi

        python -c "
from hunter.db import get_conn, migrate
from datetime import datetime, timezone
migrate()
conn = get_conn()
slug='$slug'
now = datetime.now(timezone.utc).isoformat()
conn.execute('INSERT OR IGNORE INTO plugins (slug) VALUES (?)', (slug,))
conn.execute('INSERT OR REPLACE INTO manual_reviews (plugin_slug, reviewed_at, verdict, notes, source_deleted_at) VALUES (?,?,?,?,?)', (slug, now, 'auto_v2_iter_$i', 'v2 scan: installs=$installs', now))
conn.commit()
" 2>>"$LOG"
        rm -rf "$plugin_dir"
    done
done

echo "=== Done at $(date) ===" >> "$LOG"
echo "" >> "$LOG"
[ -s "$FLAGS" ] && echo "FLAGS:" >> "$LOG" && cat "$FLAGS" >> "$LOG"
