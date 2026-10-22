#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * php-crisis-toolkit :: check (v0.1 stub)
 *
 * Defensive self-check for PHP2Shell (CVE-2026-109618 / CVE-2026-109619).
 * Version + SAPI assessment only. No exploit code. See docs/DESIGN.md.
 */

const PATCHED_FLOOR = [
    '8.5' => '8.5.12',
    '8.4' => '8.4.27',
    '8.3' => '8.3.36',
    '8.2' => '8.2.35',
    // <= 8.1: EOL, no official fix
];

// TODO v0.1:
//  [ ] 1. Detect version + branch, compare against PATCHED_FLOOR
//  [ ] 2. Detect SAPI (php_sapi_name / apache_get_modules / SERVER_SOFTWARE)
//  [ ] 3. Risk score = branch status x SAPI class (see docs/DESIGN.md)
//  [ ] 4. --json output
//  [ ] 5. --report renders templates/emergency-report.*.md

fwrite(STDOUT, "php-crisis-toolkit check — v0.1 stub, implementation in progress. See docs/DESIGN.md\n");
exit(0);
