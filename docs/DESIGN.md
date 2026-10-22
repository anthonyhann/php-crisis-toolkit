# Design notes

## SAPI detection (the core differentiator)

Public reporting around the disclosure indicates mod_php has a demonstrated
single-request unauthenticated RCE path, while PHP-FPM is exploitable under
different conditions. FrankenPHP, php-cgi and LiteSpeed (LSAPI) are also in
scope. Conclusion: risk = version branch × SAPI. A version-only check would
misjudge a large share of servers.

Detection order in `src/check.php`:

1. `php_sapi_name()` — ground truth for the current runtime.
2. When running under Apache: `apache_get_modules()` (if available) to confirm mod_php.
3. `$_SERVER['SERVER_SOFTWARE']` heuristics for LiteSpeed / Caddy-FrankenPHP.
4. FPM: fastcgi environment markers; keep heuristics conservative.
5. CLI-only access (common on shared hosting): report the CLI version, but warn
   explicitly that the web SAPI may differ, and walk the user through a
   temporary probe file (created, read once, deleted).

## Risk matrix

| Version status \ SAPI | mod_php | FPM / cgi / FrankenPHP / LSAPI | CLI-only known |
|---|---|---|---|
| Unpatched branch | CRITICAL | HIGH | WARN (web runtime unverified) |
| Patched | OK | OK | OK (still verify web runtime) |
| ≤ 8.1 (EOL) | CRITICAL + migrate | HIGH + migrate | migrate |

Output modes: human text (default), `--json` for automation, `--report` renders
`templates/emergency-report.*.md` with the findings filled in.

## Hard rules

- No exploit primitives. Assessment by version and configuration only.
- Local / own infrastructure only. No scanning of third parties.
