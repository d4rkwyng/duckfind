<?php
// Dependency-free unit checks for lib.php's pure helpers (no network, no DNS).
// Run:  php tests/run.php     -- exits non-zero on any failure.
// Covers the security-relevant pieces (SSRF IP classification, URL
// resolution, output escaping) plus regressions fixed in review passes.
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
$GLOBALS['argv'] = [__FILE__];          // df_input() falls back to argv[1] on CLI
require __DIR__ . '/../public/lib.php';
// keep any state the helpers write (pob secret) out of a real cache dir
$tmpCache = sys_get_temp_dir() . '/duckfind-test-' . getmypid();
$GLOBALS['DF_CFG']['cache_dir'] = $tmpCache;
register_shutdown_function(function () use ($tmpCache) {
    foreach (array_merge(glob($tmpCache . '/rl/.*') ?: [], glob($tmpCache . '/rl/*') ?: []) as $f) {
        if (is_file($f)) @unlink($f);
    }
    @rmdir($tmpCache . '/rl'); @rmdir($tmpCache);
});

$pass = 0; $fail = 0;
function check(string $name, $got, $want): void {
    global $pass, $fail;
    if ($got === $want) { $pass++; return; }
    $fail++;
    fwrite(STDERR, "FAIL $name\n  want: " . var_export($want, true) . "\n  got:  " . var_export($got, true) . "\n");
}

// --- SSRF: only public, routable addresses pass ------------------------------
foreach (['127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.3.104', '169.254.169.254',
          '100.89.204.83', '100.64.0.1', '0.0.0.0', '::1', 'fc00::1', 'fe80::1',
          '::ffff:127.0.0.1', '::ffff:10.0.0.1', '64:ff9b::7f00:1', '2001:db8::1',
          '198.18.0.1', '192.0.0.8', 'not-an-ip'] as $ip) {
    check("private $ip", df_ip_is_public($ip), false);
}
foreach (['1.1.1.1', '8.8.8.8', '2606:4700:4700::1111', '100.128.0.1'] as $ip) {
    check("public $ip", df_ip_is_public($ip), true);
}
check('cidr /10 edge in',  df_ip_in_cidr('100.127.255.255', '100.64.0.0/10'), true);
check('cidr /10 edge out', df_ip_in_cidr('100.128.0.0', '100.64.0.0/10'), false);
check('cidr no slash',     df_ip_in_cidr('1.2.3.4', '1.2.3.4'), false);

// URL validation that needs no DNS: literal IPs and rejected shapes
check('validate private literal', df_validate_url('http://127.0.0.1/'), null);
check('validate metadata',        df_validate_url('http://169.254.169.254/latest/'), null);
check('validate file scheme',     df_validate_url('file:///etc/passwd'), null);
check('validate gopher scheme',   df_validate_url('gopher://example.com/'), null);
check('validate ipv6 literal',    df_validate_url('http://[::1]/'), null);
check('validate odd host',        df_validate_url('http://exa_mple!.com/'), null);
$v = df_validate_url('https://1.1.1.1:8443/x');
check('validate public literal', $v === null ? null : [$v['ip'], $v['port'], $v['scheme']], ['1.1.1.1', 8443, 'https']);

// --- absolutize --------------------------------------------------------------
$b = 'https://ex.com/a/b/page.html?x=1';
check('abs relative',  absolutize($b, 'img.png'),          'https://ex.com/a/b/img.png');
check('abs dotdot',    absolutize($b, '../../c.png'),      'https://ex.com/c.png');
check('abs dotdot over root', absolutize($b, '../../../../c'), 'https://ex.com/c');
check('abs root',      absolutize($b, '/r'),               'https://ex.com/r');
check('abs protorel',  absolutize('http://ex.com/', '//cdn.ex.com/i'), 'http://cdn.ex.com/i');
check('abs absolute',  absolutize($b, 'http://other.org/'), 'http://other.org/');
check('abs fragment keeps query', absolutize($b, '#top'),  'https://ex.com/a/b/page.html?x=1#top');
check('abs query replaces', absolutize($b, '?y=2'),        'https://ex.com/a/b/page.html?y=2');
check('abs port kept', absolutize('http://ex.com:8080/a/', 'b'), 'http://ex.com:8080/a/b');
// regressions 2026-10-16: directory trailing slash, "//" inside a query
check('abs dir slash kept',   absolutize($b, 'sub/'),      'https://ex.com/a/b/sub/');
check('abs dotdot dir',       absolutize($b, '../'),       'https://ex.com/a/');
check('abs dot dir',          absolutize($b, '.'),         'https://ex.com/a/b/');
check('abs root slash',       absolutize($b, '/'),         'https://ex.com/');
check('abs dotdot to root',   absolutize('https://ex.com/a/', '../'), 'https://ex.com/');
check('abs query slashes',    absolutize($b, '/go?u=https://x.org/p/'), 'https://ex.com/go?u=https://x.org/p/');
check('abs rel + query',      absolutize($b, '../c.php?d=1#f'), 'https://ex.com/a/c.php?d=1#f');
check('abs dir listing file', absolutize('https://ex.com/pub/mac/', 'file.sit'), 'https://ex.com/pub/mac/file.sit');

// --- output escaping is ASCII-only and tag-safe ------------------------------
check('e quotes',   e('<a href="x">\'</a>'), '&lt;a href=&quot;x&quot;&gt;&#039;&lt;/a&gt;');
check('e smart',    e("\u{201C}hi\u{201D} \u{2014} ok\u{2026}"), '&quot;hi&quot; -- ok...');
check('e latin1',   e('caf' . "\u{00E9}"), 'caf&#233;');
check('e astral',   e("\u{1F986}"), '&#129414;');   // duck emoji: real codepoint, not -0x10000

// --- df_utf8: iso-8859-1 form submissions (regression 2026-10-13) ------------
check('utf8 passthrough', df_utf8('caf' . "\u{00E9}"), 'caf' . "\u{00E9}");
check('utf8 from latin1', df_utf8("caf\xE9"), 'caf' . "\u{00E9}");
check('utf8 cp1252 quote', df_utf8("\x93hi\x94"), "\u{201C}hi\u{201D}");
check('utf8 ascii',       df_utf8('plain'), 'plain');
check('e of latin1 input not blank', e(df_utf8("caf\xE9")), 'caf&#233;');
$_GET['q'] = "  na\xEFve  ";
check('df_input converts + trims', df_input('q'), 'na' . "\u{00EF}" . 've');
unset($_GET['q']);
$_GET['q'] = ['x'];
check('df_input array-safe', df_input('q'), '');
unset($_GET['q']);
check('df_str array', df_str(['x']), '');
check('df_str null', df_str(null), '');
check('df_str string', df_str('a b'), 'a b');

// --- df_feed_img: multiple <media:group>s (regression 2026-10-13) ------------
$x = simplexml_load_string('<item xmlns:media="http://search.yahoo.com/mrss/">'
   . '<media:group><media:title>no thumb here</media:title></media:group>'
   . '<media:group><media:thumbnail url="https://img.example/second.jpg"/></media:group>'
   . '<media:group><media:title>nor here</media:title></media:group></item>');
check('feed img from non-last media:group', df_feed_img($x), 'https://img.example/second.jpg');
$x = simplexml_load_string('<item><enclosure url="https://img.example/e.jpg" type="image/jpeg"/></item>');
check('feed img enclosure', df_feed_img($x), 'https://img.example/e.jpg');
check('feed img from html', df_feed_img(simplexml_load_string('<item/>'), '<p><img src="https://i.example/a.png"></p>'),
      'https://i.example/a.png');
check('feed title entities', df_feed_title(' It&#8217;s &amp; fine '), "It\u{2019}s & fine");

// --- misc helpers -------------------------------------------------------------
check('img mode array-safe', df_img_mode(['x']), 'color');
check('img mode bw',         df_img_mode('BW'), 'bw');
check('slug',                df_slug('World & U.S. News!'), 'world-u-s-news');
check('slug empty',          df_slug('!!!'), 'x');
check('is_download sit',     df_is_download('http://x.org/files/Stuffit.sit'), true);
check('is_download html',    df_is_download('http://x.org/page.html'), false);
check('is_download none',    df_is_download('http://x.org/dir/'), false);
check('shorten',             df_shorten(str_repeat('a', 80), 10), 'aaaaaaa...');
$tok = df_pob_token();
check('pob token valid',     df_pob_valid($tok), true);
check('pob token tampered',  df_pob_valid($tok . '0'), false);
check('pob token expired',   df_pob_valid((time() - 7200) . '.x'), false);

// --- df_client_ip: bare trusted_proxies entries are single hosts ----------------
$GLOBALS['DF_CFG']['trusted_proxies'] = ['2606:4700::1', '192.0.2.10'];
$_SERVER['HTTP_X_FORWARDED_FOR'] = '9.9.9.9';
$_SERVER['REMOTE_ADDR'] = '2606:4700::1';
check('xff from trusted v6 proxy', df_client_ip(), '9.9.9.9');
$_SERVER['REMOTE_ADDR'] = '2606:4700:ffff::9';   // same /32, different host
check('xff ignored, v6 neighbour', df_client_ip(), '2606:4700:ffff::9');
$_SERVER['REMOTE_ADDR'] = '192.0.2.10';
check('xff from trusted v4 proxy', df_client_ip(), '9.9.9.9');
$_SERVER['REMOTE_ADDR'] = '192.0.2.11';
check('xff ignored, v4 neighbour', df_client_ip(), '192.0.2.11');
unset($_SERVER['HTTP_X_FORWARDED_FOR'], $_SERVER['REMOTE_ADDR'], $GLOBALS['DF_CFG']['trusted_proxies']);

// --- cache GC: deletes only entries past the longest TTL, never rl/ state -----
@mkdir($tmpCache . '/ab', 0700, true); @mkdir($tmpCache . '/rl', 0700, true);
$old = $tmpCache . '/ab/old'; $mid = $tmpCache . '/ab/mid'; $ctr = $tmpCache . '/rl/daily_ai_test';
foreach ([$old => 40, $mid => 20, $ctr => 40] as $f => $days) { file_put_contents($f, 'x'); touch($f, time() - $days * 86400); }
for ($i = 0; $i < 5000 && is_file($old); $i++) df_cache_gc();   // sweep runs on ~1.5% of calls
check('gc drops entry past max TTL', is_file($old), false);
check('gc keeps 20-day entry (ebook TTL is 30d)', is_file($mid), true);
check('gc never touches rl/ counters', is_file($ctr), true);
@unlink($mid); @rmdir($tmpCache . '/ab');

// --- calc.php result formatting (regression 2026-10-16: 50+50 showed "= 1") ---
// calc.php is a page script, so run it as one; these inputs never hit the network.
function calc_cli(string $q): ?string {
    $out = (string)shell_exec(escapeshellarg(PHP_BINARY) . ' '
        . escapeshellarg(__DIR__ . '/../public/calc.php') . ' ' . escapeshellarg($q));
    return preg_match('/<b>= ([^<]*)<\/b>/', $out, $m) ? $m[1] : null;
}
foreach (['50+50' => '100', '1 km to m' => '1000 m', '2+2*(14-3)^2' => '244',
          '10^20' => '1E+20', '0.1+0.2' => '0.3', '1/3' => '0.33333333', '0-0' => '0',
          '123456789' => '123456789', '2^-30' => '9.3132257E-10', '1 mi to ft' => '5280 ft'] as $in => $want) {
    check("calc $in", calc_cli($in), $want);
}

echo "$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
