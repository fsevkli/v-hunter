# WP-Hunter

A workflow for discovering vulnerabilities in WordPress plugins through
**responsible disclosure**. It uses custom Semgrep rules to surface candidate plugins
from the public WordPress.org repository, then a human-driven manual review (assisted by
Claude Code) to find the real logic bugs and access-control gaps. Candidates are
confirmed in an isolated Docker sandbox and human-verified before a report is filed with
Patchstack / Wordfence for CVE assignment.

> **Shared for educational and experimental purposes.** It reads open-source code and
> runs PoCs only inside a sealed local sandbox. See the [Disclaimer](#disclaimer) below.

## Assigned CVEs

CVEs discovered with this pipeline and assigned through responsible disclosure:

<!-- Fill in as advisories are published. One row per CVE; link to advisories/<id>.md -->

| CVE | Plugin | Type | Severity | Advisory |
|-----|--------|------|----------|----------|
| [CVE-2026-48881](./advisories/CVE-2026-48881.md) | TrueBooker – Appointment Booking and Scheduler System (`<= 1.1.9`, fixed 1.2.0) | Broken Access Control — Missing Authorization (CWE-862) | 9.1 Critical | [advisory](./advisories/CVE-2026-48881.md) |
| [CVE-2026-54830](./advisories/CVE-2026-54830.md) | Five Star Restaurant Reservations (`<= 2.7.19`, fixed 2.7.20) | Broken Access Control | 7.5 High | [advisory](./advisories/CVE-2026-54830.md) |
| [CVE-2026-54835](./advisories/CVE-2026-54835.md) | Five Star Restaurant Menu (`<= 2.5.2`) | Broken Access Control | 7.5 High | [advisory](./advisories/CVE-2026-54835.md) |

Full write-ups live in [`advisories/`](./advisories/).

## How it works

The workflow that actually produced the CVEs below:

```
[1. Ingest + Semgrep rules] -> [2. Manual review w/ Claude Code] -> [3. Sandbox verify] -> [4. Human verify] -> [5. Report]
```

1. **Ingest + static filter.** `hunter` pulls plugin source from WordPress.org and runs
   the custom Semgrep rules in [`rules/`](./rules/) to surface candidate plugins and
   suspicious handlers (unauth AJAX endpoints, missing nonce/cap checks, etc.).
2. **Manual review.** A human reads the flagged code — with Claude Code as an assistant —
   looking for the real bugs: logic gaps, broken access control, payment-flow bypasses.
   This is where the actual findings come from, not from an automated verdict.
3. **Sandbox verification.** The candidate is reproduced against a clean WordPress in
   Docker ([`sandbox/`](./sandbox/)) to confirm it's a real, exploitable bug rather than
   a false positive.
4. **Human verification.** A person confirms the sandbox evidence and the impact.
5. **Report + disclosure.** A write-up is filed with Patchstack / Wordfence.

> ### A note on the automated LLM triager
>
> This repo also contains an automated **LLM triager** (`triager.py`, `cc_triager.py`)
> and **PoC generator** (`poc_generator.py`) that were meant to auto-confirm Semgrep
> candidates end-to-end. In practice that pipeline cost ~$40 in a single run and produced
> too many false positives to be worth it, so I dropped the fully-automated triage and
> did the review manually with Claude Code instead. **The triager code is left in the
> repo for reference, but it is not what found the bugs below.**

Modules under [`hunter/`](./hunter/):

| Module | Role | Used for the CVEs? |
|---|---|---|
| `ingestor.py` | Pull plugin source from WordPress.org SVN | Yes |
| `static_filter.py`, `pre_filter.py` | Run custom Semgrep rules (`rules/`) as a high-recall pre-filter | Yes |
| `verifier.py` (+ `sandbox/`) | Reproduce a candidate against a clean WordPress in Docker | Yes |
| `reporter.py` | Render the Patchstack/GHSA-ready markdown report | Yes |
| `review.py` | Human approval gate over candidates | Yes |
| `triager.py`, `cc_triager.py`, `call_resolver.py`, `context.py` | Experimental automated LLM triage (cross-function tracing) | No, built but not worth the cost/false positives |
| `poc_generator.py` | Experimental automated PoC drafting | No, experimental |

## Vulnerability classes

Detection rules (Semgrep) live in [`rules/`](./rules/) — SQL injection, reflected &
stored XSS, missing nonce/capability checks, arbitrary file upload, path traversal,
PHP object injection, SSRF, IDOR, prototype pollution, SSTI, REST unauth endpoints,
and privilege escalation.

## Setup

```bash
# Python 3.11+
pip install -e .

# Configure the Anthropic API key for the triager/PoC stages
cp .env.example .env   # then edit
```

CLI surface:

```bash
hunter ingest --slugs some-plugin
hunter scan    --plugin some-plugin
hunter triage  --plugin some-plugin
hunter verify  --candidate-id 42
hunter review
hunter report  --candidate-id 42
hunter pipeline --plugin some-plugin    # end-to-end
```

## Disclaimer

This repository is published for **educational and experimental purposes**. All findings
were sandbox-verified and responsibly disclosed via Patchstack/Wordfence before
publication. Do not use this tooling against systems you do not own or have explicit
permission to test.

## License

See [LICENSE](./LICENSE).
