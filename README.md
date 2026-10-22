# php-crisis-toolkit

Defensive self-check and response toolkit for the PHP2Shell crisis (CVE-2026-109618 / CVE-2026-109619).

> ⚠️ Defensive use only. No exploit code, no PoC, no attack traffic samples — in this repo, ever.

## Why this exists

On 2026-10-21 the PHP Group shipped emergency fixes for two CVSS 9.2 flaws hiding in the PHP core for over a decade. Most of the web runs PHP, and the people hit hardest are small site owners on shared hosting who don't know their PHP version and can't upgrade by themselves.

This toolkit answers three questions:

1. **Am I affected?**
2. **What exactly should I do next?**
3. **How do I buy time until I can patch?**

## Modules

| Module | Status | What it does |
|---|---|---|
| `src/check.php` | 🚧 v0.1 WIP | One-command self-check. Compares the PHP branch against the patched floor **and** detects the SAPI (mod_php / PHP-FPM / php-cgi / FrankenPHP / LiteSpeed) — exploitability differs per SAPI, so a version check alone is not enough. See `docs/DESIGN.md`. |
| `templates/` | skeleton | Plain-language emergency report (zh-CN / en), including a contact-your-hosting-provider script for shared-hosting users. |
| `waf/` | skeleton | Adaptable WAF rule templates: ModSecurity, Cloudflare, Aliyun. Defensive filtering only. |
| `watch` | planned | Watches official PHP security advisories and notifies on new releases. |

## Affected versions

| Branch | Fixed in | If older |
|---|---|---|
| 8.5.x | 8.5.12 | affected |
| 8.4.x | 8.4.27 | affected |
| 8.3.x | 8.3.36 | affected |
| 8.2.x | 8.2.35 | affected |
| ≤ 8.1 | — | EOL, no official fix planned |

Per Wiz, every PHP release since 5.4 is affected by at least one of the two flaws.

## Quick start

v0.1.0 is being built in public right now. It will be one command:

```bash
php src/check.php
```

## References

- PHP Group security advisory, 2026-10-21 (php.net)
- CERT-EU Security Advisory 2026-018
- IPA security alert (Japan), 2026-10-22
- GHSA-w8hw-w9fx-j79w (RCE via OOM corruption) / GHSA-6wmf-4rv5-p3rp (RCE via stale global state)

## License

MIT © 2026 Anthony Han ([@anthonyhann](https://github.com/anthonyhann))
