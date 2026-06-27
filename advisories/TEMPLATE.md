# CVE-YYYY-NNNNN — <Vulnerability Title>

> _Published for educational and experimental purposes. Responsibly disclosed via Patchstack._

| | |
|---|---|
| **CVE** | CVE-YYYY-NNNNN |
| **Plugin** | `plugin-slug` (Plugin Display Name) |
| **Affected versions** | `<= X.Y.Z` |
| **Fixed in** | `X.Y.Z+1` |
| **Vulnerability type** | <e.g. SQL Injection> (CWE-NNN) |
| **CVSS 3.1** | `<score>` / `<vector>` |
| **Authentication** | <Unauthenticated / Subscriber+ / Admin> |
| **Researcher** | <Your name / handle> |
| **Disclosure** | <Patchstack / Wordfence / GHSA> — <date> |

## Summary

One-paragraph plain-language description of what the bug is and why it matters.

## Affected code

`path/to/file.php` (around line N):

```php
// the vulnerable code, with the bug highlighted in a comment
```

Reachability: which hook/endpoint exposes this (`wp_ajax_*`, `admin-post.php`, REST route),
and what privilege level reaches it.

## Steps to reproduce

1. Install `plugin-slug` version `X.Y.Z` on a test WordPress instance.
2. ...
3. ...

## Proof of concept

```bash
curl ...
```

Expected result: <observable impact — e.g. dumps a row from wp_users, writes a file, etc.>

## Impact

What an attacker gains (data disclosure, RCE, privilege escalation, etc.) and under what conditions.

## Remediation

What the fix is / what the vendor changed.

## Timeline

- `YYYY-MM-DD` — Reported to vendor / Patchstack
- `YYYY-MM-DD` — Vendor acknowledged
- `YYYY-MM-DD` — Patched version released
- `YYYY-MM-DD` — CVE assigned
- `YYYY-MM-DD` — Public disclosure
