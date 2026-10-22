# PHP2Shell Emergency Assessment Report (template)

- Generated: {generated_at}
- Host: {host_label}
- Tool: php-crisis-toolkit {tool_version}

## Verdict

Risk level: **{risk_level}** (CRITICAL / HIGH / WARN / OK)

## Environment

- PHP version: {php_version} (branch {branch})
- SAPI: {sapi}
- Patched floor for this branch: {patched_floor}

## Immediate actions (in order)

1. Upgrade to 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 or later.
2. On shared hosting and can't upgrade yourself? Send your provider:

   > My site runs PHP {php_version}. On 2026-10-21 the PHP Group released
   > emergency fixes for two CVSS 9.2 flaws (CVE-2026-109618 / CVE-2026-109619).
   > Please confirm your patch plan and ETA for the PHP runtime, and whether
   > WAF mitigation rules are active in the meantime.

3. Until patched: deploy WAF rules (see waf/ in this repo).
4. PHP 8.1 and earlier receive no official fix — plan a migration.

## Official sources

- PHP Group security advisory (2026-10-21, php.net)
- CERT-EU 2026-018 / IPA alert (2026-10-22)
