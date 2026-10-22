# WAF rule templates (planned for v0.2)

Defensive traffic-filtering templates only. No detection-by-exploit.

- `modsecurity/` — ModSecurity custom rules (CRS-compatible)
- `cloudflare/` — Cloudflare WAF custom rule expressions
- `aliyun/` — 阿里云 WAF 配置指引（中文）

Until these land, apply your vendor's emergency ruleset for
CVE-2026-109618 / CVE-2026-109619 — major vendors shipped managed rules
within 24h of disclosure.
