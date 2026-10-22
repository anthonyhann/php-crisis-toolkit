#!/usr/bin/env php
<?php
/**
 * php-crisis-toolkit :: check
 *
 * Defensive self-check for PHP2Shell (CVE-2026-109618 / CVE-2026-109619).
 * Version + SAPI assessment only. No exploit code. See docs/DESIGN.md.
 *
 * Deliberately written for PHP >= 5.4: this tool must run on the vulnerable
 * fleet, so no scalar type hints, no null coalescing, no short closures.
 *
 * Exit codes: 0 = OK, 1 = WARN, 2 = HIGH, 3 = CRITICAL
 */

define('PCT_VERSION', '0.1.0');

$PCT_PATCHED_FLOOR = array(
    '8.5' => '8.5.12',
    '8.4' => '8.4.27',
    '8.3' => '8.3.36',
    '8.2' => '8.2.35',
    // <= 8.1: EOL, no official fix
);

// ---------------------------------------------------------------- args ----

function pct_usage()
{
    return "php-crisis-toolkit check v" . PCT_VERSION . "\n"
        . "Usage: php src/check.php [--json] [--report=zh-CN|en] [--help]\n"
        . "\n"
        . "  --json            machine-readable result\n"
        . "  --report=zh-CN    write php2shell-report.zh-CN.md to current directory\n"
        . "  --report=en       write php2shell-report.en.md to current directory\n"
        . "  --help            this message\n";
}

$PCT_OPTS = array('json' => false, 'report' => null, 'help' => false);
foreach (array_slice($argv, 1) as $arg) {
    if ($arg === '--json') {
        $PCT_OPTS['json'] = true;
    } elseif ($arg === '--help' || $arg === '-h') {
        $PCT_OPTS['help'] = true;
    } elseif (preg_match('/^--report(?:=(zh-CN|en))?$/', $arg, $m)) {
        $PCT_OPTS['report'] = isset($m[1]) ? $m[1] : 'zh-CN';
    } else {
        fwrite(STDERR, "Unknown option: {$arg}\n" . pct_usage());
        exit(64);
    }
}
if ($PCT_OPTS['help']) {
    fwrite(STDOUT, pct_usage());
    exit(0);
}

// ------------------------------------------------------ version status ----

function pct_branch_of($version)
{
    $parts = explode('.', $version);
    return $parts[0] . '.' . (isset($parts[1]) ? $parts[1] : '0');
}

function pct_version_status($version, $floors)
{
    $branch = pct_branch_of($version);
    if (isset($floors[$branch])) {
        $patched = version_compare($version, $floors[$branch], '>=');
        return array(
            'branch' => $branch,
            'status' => $patched ? 'patched' : 'unpatched',
            'patched_floor' => $floors[$branch],
            'note' => $patched ? '' : 'Below the patched floor for this branch.',
        );
    }
    if (version_compare($version, '8.2.0', '<')) {
        $note = 'PHP ' . $branch . ' is end-of-life: no official fix for PHP2Shell.';
        if (version_compare($version, '5.4.0', '<')) {
            $note .= ' Versions below 5.4 predate the confirmed-affected range but are long EOL.';
        }
        return array('branch' => $branch, 'status' => 'eol', 'patched_floor' => null, 'note' => $note);
    }
    // Newer than the 8.5 line: the fix is assumed to be included.
    return array('branch' => $branch, 'status' => 'patched', 'patched_floor' => null,
        'note' => 'Branch is newer than 8.5; fix assumed included.');
}

// ---------------------------------------------------------- SAPI detect ----

function pct_detect_sapi()
{
    $sapi = php_sapi_name();
    $info = array(
        'sapi' => $sapi,
        'class' => 'other-web',
        'web_runtime_verified' => true,
        'server_software' => isset($_SERVER['SERVER_SOFTWARE']) ? $_SERVER['SERVER_SOFTWARE'] : '',
        'evidence' => array('php_sapi_name()=' . $sapi),
    );

    if ($sapi === 'cli' || $sapi === 'phpdbg' || $sapi === 'embed') {
        $info['class'] = 'cli';
        $info['web_runtime_verified'] = false;
        $info['evidence'][] = 'CLI context: web SAPI not observable from here';
        return $info;
    }
    if ($sapi === 'apache2handler') {
        $info['class'] = 'mod_php';
        if (function_exists('apache_get_modules')) {
            $mods = apache_get_modules();
            if (is_array($mods)) {
                $info['evidence'][] = 'apache_get_modules() confirms mod_php handler';
            }
        }
    } elseif ($sapi === 'fpm-fcgi') {
        $info['class'] = 'fpm';
    } elseif ($sapi === 'litespeed') {
        $info['class'] = 'litespeed';
    } elseif ($sapi === 'frankenphp') {
        $info['class'] = 'frankenphp';
    } elseif ($sapi === 'cgi-fcgi' || $sapi === 'cgi') {
        $info['class'] = 'cgi';
    }

    // SERVER_SOFTWARE heuristics refine ambiguous cases.
    $sw = $info['server_software'];
    if ($sw !== '') {
        if (stripos($sw, 'litespeed') !== false && $info['class'] !== 'mod_php') {
            $info['class'] = 'litespeed';
            $info['evidence'][] = 'SERVER_SOFTWARE contains LiteSpeed';
        } elseif (stripos($sw, 'caddy') !== false && $info['class'] === 'cgi') {
            $info['class'] = 'frankenphp';
            $info['evidence'][] = 'SERVER_SOFTWARE contains Caddy (FrankenPHP likely)';
        }
    }
    return $info;
}

// ------------------------------------------------------------ risk score ----

function pct_risk($vstatus, $sapi)
{
    $migrate = ($vstatus['status'] === 'eol');
    if ($vstatus['status'] === 'patched') {
        if (!$sapi['web_runtime_verified']) {
            return array('level' => 'WARN', 'exit' => 1,
                'reason' => 'CLI runtime is patched, but the web SAPI was not verified from here. Re-run under the web SAPI or probe it.');
        }
        return array('level' => 'OK', 'exit' => 0, 'reason' => 'Patched release on the observed runtime.');
    }
    if (!$sapi['web_runtime_verified']) {
        // CLI unpatched/EOL on a host almost always means the web runtime matches.
        return array('level' => 'HIGH', 'exit' => 2,
            'reason' => 'CLI runtime is ' . $vstatus['status'] . '; the web SAPI on the same host is very likely identical. Verify the web SAPI to be sure.',
            'migrate' => $migrate);
    }
    if ($sapi['class'] === 'mod_php') {
        return array('level' => 'CRITICAL', 'exit' => 3,
            'reason' => 'Unpatched mod_php: a single-request unauthenticated RCE path has been publicly demonstrated.',
            'migrate' => $migrate);
    }
    return array('level' => 'HIGH', 'exit' => 2,
        'reason' => 'Unpatched ' . $sapi['class'] . ' runtime: exploitable under different conditions than mod_php, still unauthenticated RCE class.',
        'migrate' => $migrate);
}

// --------------------------------------------------------------- report ----

function pct_render_report($lang, $data)
{
    $file = __DIR__ . '/../templates/emergency-report.' . $lang . '.md';
    if (!is_file($file)) {
        fwrite(STDERR, "Template not found: {$file}\n");
        return null;
    }
    $tpl = file_get_contents($file);
    $map = array(
        '{generated_at}' => $data['generated_at'],
        '{host_label}' => $data['host'],
        '{tool_version}' => PCT_VERSION,
        '{risk_level}' => $data['risk']['level'],
        '{php_version}' => $data['php']['version'],
        '{branch}' => $data['php']['branch'],
        '{sapi}' => $data['sapi']['sapi'] . ' (' . $data['sapi']['class'] . ')',
        '{patched_floor}' => $data['php']['patched_floor'] ? $data['php']['patched_floor'] : '—',
    );
    $out = strtr($tpl, $map);
    $target = getcwd() . '/php2shell-report.' . $lang . '.md';
    if (file_put_contents($target, $out) === false) {
        fwrite(STDERR, "Cannot write {$target}\n");
        return null;
    }
    return $target;
}

// ------------------------------------------------------------------ run ----

$vstatus = pct_version_status(PHP_VERSION, $PCT_PATCHED_FLOOR);
$vstatus['version'] = PHP_VERSION;
$sapi = pct_detect_sapi();
$risk = pct_risk($vstatus, $sapi);

$result = array(
    'tool' => 'php-crisis-toolkit check',
    'tool_version' => PCT_VERSION,
    'generated_at' => date('c'),
    'host' => function_exists('gethostname') ? gethostname() : 'unknown',
    'cve' => array('CVE-2026-109618', 'CVE-2026-109619'),
    'php' => $vstatus,
    'sapi' => $sapi,
    'risk' => $risk,
    'actions' => array(),
);

if ($risk['level'] === 'OK') {
    $result['actions'][] = 'No action required on the observed runtime. Re-check after the next PHP update.';
} else {
    if ($vstatus['status'] === 'unpatched') {
        $result['actions'][] = 'Upgrade PHP to ' . $vstatus['patched_floor'] . ' or later (branch ' . $vstatus['branch'] . ').';
    }
    if (!empty($risk['migrate'])) {
        $result['actions'][] = 'This branch is EOL and receives no fix: plan a migration to a supported branch (8.2+).';
    }
    $result['actions'][] = 'Until patched: deploy your vendor\'s emergency WAF rules (see waf/ in this repo).';
    $result['actions'][] = 'Shared hosting? Send your provider the script from templates/emergency-report.' . ($PCT_OPTS['report'] === 'en' ? 'en' : 'zh-CN') . '.md';
    if (!$sapi['web_runtime_verified']) {
        $result['actions'][] = 'Verify the web SAPI: drop a temporary probe file with <?php php_sapi_name(); phpversion(); and delete it right after.';
    }
}

if ($PCT_OPTS['json']) {
    fwrite(STDOUT, json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");
} else {
    $L = array();
    $L[] = 'php-crisis-toolkit check v' . PCT_VERSION . ' — PHP2Shell (CVE-2026-109618 / CVE-2026-109619)';
    $L[] = str_repeat('-', 72);
    $L[] = 'Host:    ' . $result['host'];
    $L[] = 'PHP:     ' . PHP_VERSION . ' (branch ' . $vstatus['branch'] . ', status: ' . $vstatus['status']
        . ($vstatus['patched_floor'] ? ', patched floor: ' . $vstatus['patched_floor'] : '') . ')';
    $L[] = 'SAPI:    ' . $sapi['sapi'] . ' [' . $sapi['class'] . ']'
        . ($sapi['server_software'] !== '' ? ' — ' . $sapi['server_software'] : '')
        . ($sapi['web_runtime_verified'] ? '' : ' — web runtime NOT verified');
    $L[] = 'Risk:    ' . $risk['level'] . ' — ' . $risk['reason'];
    if ($vstatus['note'] !== '') {
        $L[] = 'Note:    ' . $vstatus['note'];
    }
    $L[] = '';
    $L[] = 'Actions:';
    foreach ($result['actions'] as $i => $a) {
        $L[] = '  ' . ($i + 1) . '. ' . $a;
    }
    fwrite(STDOUT, implode("\n", $L) . "\n");
}

if ($PCT_OPTS['report'] !== null) {
    $path = pct_render_report($PCT_OPTS['report'], $result);
    if ($path !== null) {
        fwrite(STDOUT, "Report written: {$path}\n");
    }
}

exit($risk['exit']);
