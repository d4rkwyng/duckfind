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
          '198.18.0.1', '192.0.0.8', 'not-an-ip',
          '2002:7f00:1::1', '2002:c0a8:0101::1', '2001:0:4136:e378:8000:63bf:3fff:fdd2'] as $ip) {
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

// --- df_to_utf8: page charset labels (regression 2026-10-24) -----------------
// An encoding mbstring doesn't know is a ValueError on PHP 8; the reader 500'd.
check('to_utf8 latin1 header', df_to_utf8("caf\xE9", 'text/html; charset=iso-8859-1'), 'caf' . "\u{00E9}");
check('to_utf8 meta charset',  df_to_utf8("<meta charset=windows-1252>\x93x\x94"), "<meta charset=windows-1252>\u{201C}x\u{201D}");
check('to_utf8 unknown label', df_to_utf8("caf\xE9", 'text/html; charset=windows-874'), "caf\xE9");
check('to_utf8 typo label',    df_to_utf8('ok', 'text/html; charset=iso-bogus'), 'ok');

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
// X-Forwarded-For is appended to: the client controls its LEFT end
$_SERVER['REMOTE_ADDR'] = '192.0.2.10';
$_SERVER['HTTP_X_FORWARDED_FOR'] = '6.6.6.6, 9.9.9.9';            // client sent "6.6.6.6"
check('xff spoofed left entry ignored', df_client_ip(), '9.9.9.9');
$_SERVER['HTTP_X_FORWARDED_FOR'] = '6.6.6.6, 9.9.9.9, 2606:4700::1';   // two trusted hops
check('xff skips trusted hops', df_client_ip(), '9.9.9.9');
$_SERVER['HTTP_X_FORWARDED_FOR'] = 'junk, 9.9.9.9';
check('xff garbage left of client', df_client_ip(), '9.9.9.9');
$_SERVER['HTTP_X_FORWARDED_FOR'] = '9.9.9.9, junk';
check('xff garbage at right end', df_client_ip(), '192.0.2.10');
$_SERVER['HTTP_CF_CONNECTING_IP'] = '8.8.4.4';
check('cf-connecting-ip preferred', df_client_ip(), '8.8.4.4');
unset($_SERVER['HTTP_CF_CONNECTING_IP']);
$_SERVER['REMOTE_ADDR'] = '203.0.113.5';
check('xff ignored from untrusted peer', df_client_ip(), '203.0.113.5');
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

// --- about.php: flood-protection disclosure + 'page' bucket listing --------------
// Rendered in-process (about.php require()s lib.php, which is already loaded, so its
// require line is stripped). NOTE: df_rate_ok() returns true under CLI, so this checks
// rendering/config wiring only -- the per-IP enforcement itself is NOT exercised here.
function about_html(array $cfg): string {
    $saved = $GLOBALS['DF_CFG'];
    $GLOBALS['DF_CFG'] = array_merge($saved, $cfg);
    $src = preg_replace('/^require __DIR__ \. \'\/lib\.php\';$/m', '', (string)file_get_contents(__DIR__ . '/../public/about.php'), 1, $n);
    ob_start();
    try { eval('?>' . $src); } finally { $out = (string)ob_get_clean(); $GLOBALS['DF_CFG'] = $saved; }
    return $n === 1 ? $out : '';
}
$aboutOff = about_html(['flood_protection' => false]);
$aboutOn  = about_html(['flood_protection' => true]);
check('about renders', strpos($aboutOff, '<h2>Privacy</h2>') !== false, true);
check('about: no flood disclosure when flag false', stripos($aboutOff, 'temporarily blocked at the firewall') !== false, false);
check('about: flood disclosure when flag true', stripos($aboutOn, 'temporarily blocked at the firewall') !== false, true);
check('about: disclosure states the 7-day ban length', strpos($aboutOn, 'up to 7 days') !== false, true);
check('example config: flood_protection defaults off', df_cfg('flood_protection', null), false);
check('about lists page bucket', strpos($aboutOff, '120 page views per minute') !== false, true);
check('about lists page bucket w/ custom limit', strpos(about_html(['rate' => ['page' => [7, 60]]]), '7 page views per minute') !== false, true);
check('example config has page bucket', df_cfg('rate', [])['page'] ?? null, [120, 60]);

// --- streaming concurrency slots (added 2026-11-07) ----------------------------
// Real flock()s on real files in the test rate dir. flock locks belong to the
// open file, so two fopen()s in this one process contend exactly like two
// php-fpm workers would; the abort case uses a genuine second process.
$GLOBALS['DF_CFG']['stream_max_per_client'] = 2;
$GLOBALS['DF_CFG']['stream_max_global'] = 4;
$_SERVER['REMOTE_ADDR'] = '198.51.100.1';
check('slot: first acquire',  df_slot_acquire(), 0);
check('slot: second acquire', df_slot_acquire(), 0);
check('slot: per-client cap', df_slot_acquire(), 429);
df_slot_release();
check('slot: free again after release', df_slot_acquire(), 0);
check('slot: release is idempotent', (function () { df_slot_release(); df_slot_release(); return df_slot_acquire(); })(), 0);
df_slot_acquire();                                   // A now holds 2 of the 4 global slots
$_SERVER['REMOTE_ADDR'] = '198.51.100.2';
check('slot: other client unaffected', df_slot_acquire(), 0);
check('slot: other client 2nd',        df_slot_acquire(), 0);   // global now 4/4
$_SERVER['REMOTE_ADDR'] = '198.51.100.3';
check('slot: global cap', df_slot_acquire(), 503);
df_slot_release();
// a 503 must hand back the per-client slot it briefly took, else the client
// would be charged for a stream that never ran
check('slot: global refusal leaked nothing (1)', df_slot_acquire(), 0);
check('slot: global refusal leaked nothing (2)', df_slot_acquire(), 0);
df_slot_release();
$slotFiles = array_map('basename', array_merge(glob($tmpCache . '/rl/slot_*') ?: [], glob($tmpCache . '/rl/.slotg_*') ?: []));
check('slot files use the salted hash, never the address',
      array_values(array_filter($slotFiles, fn($n) => !preg_match('/^(slot_[0-9a-f]{40}_\d|\.slotg_\d)$/', $n))), []);
check('slot files hold no data', array_sum(array_map(fn($n) => filesize($tmpCache . '/rl/' . $n), $slotFiles)), 0);
// abort: a worker holding a slot is killed outright (SIGKILL, no shutdown
// handler runs) -- the kernel must drop its lock and free the slot
$GLOBALS['DF_CFG']['stream_max_per_client'] = 1;
$_SERVER['REMOTE_ADDR'] = '198.51.100.9';
$child = 'require ' . var_export(__DIR__ . '/../public/lib.php', true) . ';'
       . '$GLOBALS["DF_CFG"]["cache_dir"] = ' . var_export($tmpCache, true) . ';'
       . '$GLOBALS["DF_CFG"]["stream_max_per_client"] = 1;'
       . '$_SERVER["REMOTE_ADDR"] = "198.51.100.9";'
       . 'echo df_slot_acquire(), "\n"; fflush(STDOUT); sleep(30);';
$cp = proc_open([PHP_BINARY, '-r', $child], [1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'w']], $cpipes);
$childGot = is_resource($cp) ? trim((string)fgets($cpipes[1])) : 'no child';
check('slot: child process acquired', $childGot, '0');
check('slot: held by another process', df_slot_acquire(), 429);
if (is_resource($cp)) { proc_terminate($cp, 9); fclose($cpipes[1]); proc_close($cp); }
check('slot: freed after the holder is killed', df_slot_acquire(), 0);
df_slot_release();
unset($_SERVER['REMOTE_ADDR'], $GLOBALS['DF_CFG']['stream_max_per_client'], $GLOBALS['DF_CFG']['stream_max_global']);

// --- feed negative cache (added 2026-11-07) -------------------------------------
// A private-IP literal fails SSRF validation with no network access at all.
$deadFeed = 'http://127.0.0.1/feed.xml';
check('dead feed returns nothing', df_feed_items($deadFeed, 5), []);
check('dead feed is negative-cached', df_cache_get('feedfail:' . $deadFeed, 600), '1');
check('dead feed not cached as a success', df_cache_get('feed2:' . $deadFeed, 1800), null);
foreach (['feedfail:', 'feed2:'] as $pfx) {
    $cf = df_cache_path($pfx . $deadFeed);
    @unlink($cf); @rmdir(dirname($cf));
}

// --- browser-proof measurement (pob counters) -------------------------------
$tok2 = df_pob_token();
check('pob classify valid cookie',  df_pob_classify($tok2, 'Mozilla/5.0'), 'yes');
check('pob classify valid + bot UA', df_pob_classify($tok2, 'Googlebot/2.1'), 'yes');
check('pob classify no cookie',     df_pob_classify('', 'Mozilla/5.0 (Macintosh)'), 'no');
check('pob classify bad cookie',    df_pob_classify('123.bogus', 'curl/8.4'), 'no');
check('pob classify empty UA',      df_pob_classify('', ''), 'no');
check('pob classify googlebot',     df_pob_classify('', 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'), 'bot');
check('pob classify bingbot',       df_pob_classify('', 'Mozilla/5.0 (compatible; bingbot/2.0)'), 'bot');
$b0 = df_daily_count('pobno');
df_daily_inc('pobno');
check('pob daily counter bumps', df_daily_count('pobno'), $b0 + 1);
check('pob daily file is aggregate', basename(df_daily_file('pobno')), 'daily_pobno_' . gmdate('Ymd'));
// legacy-browser exemption from the cookie gate (never gated, counted as 'legacy')
foreach ([
    'MacWeb/2.0 (Macintosh; PPC)',
    'NCSA Mosaic/2.0.0b4 (Windows x86)',
    'MacMosaicB6  libwww2.09',   // NCSA Mosaic 1.0.3 for Mac, from the binary's resource fork
    'NCSA_Mosaic/2.7b5 (X11;Linux 2.0.0 i686) libwww/2.12 modified',
    'Mozilla/0.9 Beta (Windows)',
    'Mozilla/1.1N (Macintosh; I; PPC)',
    'Mozilla/3.01 (Macintosh; I; PPC)',
    'Mozilla/4.08 [en] (Macintosh; I; PPC, Nav)',
    'Mozilla/4.0 (compatible; MSIE 5.0; Mac_PowerPC)',
    'Mozilla/2.0 (compatible; MSIE 3.02; Windows 95)',
    'iCab/2.9.9 (Macintosh; U; PPC)',
    'Lynx/2.8.9rel.1 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/1.1.1d',
    'Links (2.29; Linux 6.1.0 x86_64; GNU C 12.2; text)',
    'w3m/0.5.3+git20230121',
    'xChaos_Arachne/5.1.89;GPL,386+',
    'Dillo/3.0.5',
    'NetSurf/3.10 (RISC OS)',
    'Mozilla/5.0 (Macintosh; U; PPC Mac OS; en-US; rv:9.3.3) Gecko/20120427 Classilla/CFM',
    'Mozilla/5.0 (compatible; U; Haiku x86_64; en-us) AppleWebKit/537.36 (KHTML, like Gecko) WebPositive/1.2 Safari/537.36',
    'Cyberdog/2.0 (Macintosh; PPC)',
    'OmniWeb/4.1.1-v423',
    'Opera/6.03 (Macintosh; U; PPC)',
    'Mozilla/4.0 (compatible; MSIE 5.0; Windows 98) Opera 6.0 [en]',
    'AWeb/3.4 (AmigaOS)',
    'IBrowse/2.4 (AmigaOS 3.9)',
    'Voyager/3.3 (AmigaOS)',
] as $ua) check("pob legacy: $ua", df_pob_classify('', $ua), 'legacy');
foreach ([
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:132.0) Gecko/20100101 Firefox/132.0',
    'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)',
    'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)',
    'Mozilla/4.0 (compatible; Chrome/120.0)',
    'Opera/9.80 (Windows NT 6.1) Presto/2.12.388 Version/12.18',
    'OmniWeb/v622.8.0',
    'Mozilla/5.0',
    'python-requests/2.31',
    '',
] as $ua) check("pob not legacy: $ua", df_pob_classify('', $ua), 'no');
check('pob legacy with valid cookie is yes', df_pob_classify($tok2, 'Lynx/2.8.9rel.1'), 'yes');
check('pob gate default on', (bool)df_cfg('pob_gate', true), true);

// --- expensive-path gate (df_require_browser_proof): cookieless vintage pass --
// Run in a child process (it exits); same tmp cache dir, so the pob secret and
// the daily counters are shared with this process.
function pob_gate_run(string $ua, array $cookie = [], array $get = [], array $cfg = [], bool $allowLegacy = true): string {
    $code = '$GLOBALS["argv"] = [];'
          . 'require ' . var_export(__DIR__ . '/../public/lib.php', true) . ';'
          . '$GLOBALS["DF_CFG"] = array_merge($GLOBALS["DF_CFG"] ?? [], ' . var_export(['cache_dir' => $GLOBALS['tmpCache']] + $cfg, true) . ');'
          . '$_SERVER["HTTP_USER_AGENT"] = ' . var_export($ua, true) . ';'
          . '$_SERVER["SCRIPT_NAME"] = "/read.php"; $_SERVER["QUERY_STRING"] = "url=x";'
          . '$_COOKIE = ' . ($cookie === [] ? '[]' : '["df_pob" => df_pob_token()]') . ';'
          . '$_GET = ' . var_export($get, true) . ';'
          . 'df_require_browser_proof(' . ($allowLegacy ? '' : 'false') . '); echo "PASSED";';
    return (string)shell_exec(escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg($code) . ' 2>&1');
}
$x0 = df_daily_count('pobxlegacy');
foreach (['MacWeb/2.0 (Macintosh; I; 68K)', 'Lynx/2.8.9rel.1 libwww-FM/2.14', 'NCSA_Mosaic/2.0 (Windows 3.1)',
          'iCab/2.9.9 (Macintosh; U; PPC)', 'Mozilla/3.04 (Macintosh; I; PPC)'] as $ua) {
    check("pob gate: cookieless legacy passes: $ua", pob_gate_run($ua), 'PASSED');
}
check('pob gate: legacy passes counted (pobxlegacy)', df_daily_count('pobxlegacy'), $x0 + 5);
check('pob gate: pobxlegacy file is aggregate', basename(df_daily_file('pobxlegacy')), 'daily_pobxlegacy_' . gmdate('Ymd'));
check('pob gate: legacy passes even with pob_gate off', pob_gate_run('Lynx/2.8.9rel.1', [], [], ['pob_gate' => false]), 'PASSED');
$x0 = df_daily_count('pobxlegacy');
$modern = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15';
check('pob gate: modern cookieless not passed (302)', pob_gate_run($modern), '');
check('pob gate: modern cookieless 2nd hit gets cookies page',
      strpos(pob_gate_run($modern, [], ['_pob' => '1']), 'Cookies are required for this feature') !== false, true);
check('pob gate: empty UA not passed', pob_gate_run(''), '');
check('pob gate: curl not passed', pob_gate_run('curl/8.4.0'), '');
check('pob gate: googlebot not passed', pob_gate_run('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'), '');
check('pob gate: old-looking bot UA not exempted', pob_gate_run('Mozilla/4.0 (compatible; bingbot/2.0)'), '');
check('pob gate: modern with valid cookie passes', pob_gate_run($modern, ['df_pob' => 1]), 'PASSED');
check('pob gate: legacy with valid cookie passes', pob_gate_run('Lynx/2.8.9rel.1', ['df_pob' => 1]), 'PASSED');
check('pob gate strict (ask.php): cookieless legacy not passed', pob_gate_run('Lynx/2.8.9rel.1', [], [], [], false), '');
check('pob gate strict (ask.php): legacy with cookie passes', pob_gate_run('Lynx/2.8.9rel.1', ['df_pob' => 1], [], [], false), 'PASSED');
check('pob gate: no pobxlegacy for blocked/bot/cookie/strict hits', df_daily_count('pobxlegacy'), $x0);
check('ask.php keeps the strict gate', strpos((string)file_get_contents(__DIR__ . '/../public/ask.php'), 'df_require_browser_proof(false);') !== false, true);

// --- DDG search canary: zero parsed results -> ok / markup / blocked ---------
$ddgOk = '<html><body class="body--html"><form><input id="search_form_input_homepage" name="q"></form>'
       . '<div class="serp__results"><div id="links" class="results"></div></div></body></html>';
check('ddg zero results, containers present', df_ddg_page_kind($ddgOk, 200), 'ok');
check('ddg links div only (1 marker)', df_ddg_page_kind('<div id="links" class="results"></div>', 200), 'markup');
check('ddg markup changed', df_ddg_page_kind('<html><body><div class="new-layout"></div></body></html>', 200), 'markup');
check('ddg empty body', df_ddg_page_kind('', 200), 'markup');
check('ddg anomaly challenge', df_ddg_page_kind('<div class="anomaly-modal__modal  is-ie"></div>', 202), 'blocked');
check('ddg anomaly markup on a 200', df_ddg_page_kind('<div class="anomaly-modal__mask"></div>' . $ddgOk, 200), 'blocked');
check('ddg non-200 with containers', df_ddg_page_kind($ddgOk, 202), 'blocked');
// real html-endpoint challenge (trimmed from a fetch made 2026-11-07)
$ddgChal = (string)file_get_contents(__DIR__ . '/fixtures/ddg-html-challenge.html');
check('ddg real challenge on a 200', df_ddg_page_kind($ddgChal, 200), 'blocked');

// --- DDG redirect unwrapping (shared by html and lite parsers) ---------------
check('uddg unwrap', ddg_real_url('//duckduckgo.com/l/?uddg=https%3A%2F%2Fwww.sierra.com%2Fclearance~1%2F&rut=54'), 'https://www.sierra.com/clearance~1/');
check('uddg js rejected', ddg_real_url('//duckduckgo.com/l/?uddg=javascript%3Aalert(1)'), 'https://duckduckgo.com/l/?uddg=javascript%3Aalert(1)');
check('protocol-relative', ddg_real_url('//ex.org/a'), 'https://ex.org/a');
check('relative rejected', ddg_real_url('/lite/?q=x'), '');

// --- DDG Lite fallback parser + canary (real pages fetched from bespin) ------
// ddg-lite-results.html: q=sierra on-line, 2026-11-07, results 1, 2, 5 and 11
// of 11 kept verbatim (others and the region <option> list cut for size).
$lite = (string)file_get_contents(__DIR__ . '/fixtures/ddg-lite-results.html');
$lr = parse_ddg_lite($lite);
check('lite: result count', count($lr), 4);
check('lite: first result', $lr[0] ?? null, ['title' => 'Official site', 'url' => 'https://www.sierragames.com/', 'snippet' => 'Sierra Entertainment']);
check('lite: uddg unwrapped', array_column($lr, 'url'), ['https://www.sierragames.com/',
      'https://en.wikipedia.org/wiki/Sierra_Entertainment', 'https://www.sierra.com/', 'https://www.facebook.com/SierraOnLineUniverse/']);
check('lite: entity in title', $lr[2]['title'] ?? null, 'Sierra: Shop Active & Outdoor Apparel, Footwear & Gear from Top Brands');
check('lite: snippet text, bold stripped, whitespace collapsed', $lr[2]['snippet'] ?? null,
      'Shop active and outdoor apparel, footwear, and gear from top brands at Sierra for your next adventure.');
check('lite: entity in snippet', strpos($lr[1]['snippet'] ?? '', "King's Quest") !== false, true);
check('lite: zero-click link not a result', in_array('Sierra Entertainment', array_column($lr, 'title'), true), false);
check('lite: shape matches parse_ddg', array_keys($lr[0] ?? []), ['title', 'url', 'snippet']);
// a result whose optional snippet row is absent must not borrow the next row
$noSnip = preg_replace('#<tr>\s*<td>&nbsp;&nbsp;&nbsp;</td>\s*<td class=\'result-snippet\'>\s*Sierra Entertainment\s*</td>\s*</tr>#', '', $lite, 1, $n1);
check('lite: snippet row removed (test setup)', $n1, 1);
check('lite: missing snippet row -> empty snippet', parse_ddg_lite($noSnip)[0]['snippet'] ?? null, '');
check('lite: next result keeps its snippet', strpos(parse_ddg_lite($noSnip)[1]['snippet'] ?? '', 'Sierra Entertainment, Inc.') === 0, true);
// a DDG-hosted link (ad / internal) is skipped like parse_ddg does
$adLite = str_replace('//duckduckgo.com/l/?uddg=https%3A%2F%2Fwww.sierragames.com%2F', '//duckduckgo.com/y.js?ad_domain=x', $lite, $n2);
check('lite: ad-link setup', $n2, 1);
check('lite: duckduckgo-hosted link skipped', count(parse_ddg_lite($adLite)), 3);
check('lite: empty body', parse_ddg_lite(''), []);
// canary (only consulted when the parser found nothing)
$liteZero = (string)file_get_contents(__DIR__ . '/fixtures/ddg-lite-zero.html');
check('lite zero page parses empty', parse_ddg_lite($liteZero), []);
check('lite canary: real zero-results page', df_ddg_lite_page_kind($liteZero, 200), 'ok');
check('lite canary: zero page non-200', df_ddg_lite_page_kind($liteZero, 202), 'blocked');
check('lite canary: anomaly challenge', df_ddg_lite_page_kind($ddgChal, 200), 'blocked');
check('lite canary: html-endpoint page is not lite', df_ddg_lite_page_kind($ddgOk, 200), 'markup');
check('lite canary: empty body', df_ddg_lite_page_kind('', 200), 'markup');
check('lite canary: results page with result class renamed',
      [parse_ddg_lite(str_replace("class='result-link'", "class='res-link'", $lite)),
       df_ddg_lite_page_kind(str_replace("class='result-link'", "class='res-link'", $lite), 200)], [[], 'markup']);
check('lite canary: no-results box without the lite form',
      df_ddg_lite_page_kind(preg_replace('#<form[^>]*>#', '<form>', $liteZero), 200), 'markup');
check('html canary: lite zero page is not an html page', df_ddg_page_kind($liteZero, 200), 'markup');

df_cache_put('canarytest', 'x');
df_cache_del('canarytest');
check('cache del removes entry', df_cache_get('canarytest', 600), null);

// --- atomic capped daily counter ---------------------------------------------
$cb = 'captest' . getmypid();
check('capped: 1st under cap', df_daily_inc_capped($cb, 2), true);
check('capped: 2nd reaches cap', df_daily_inc_capped($cb, 2), true);
check('capped: 3rd refused', df_daily_inc_capped($cb, 2), false);
check('capped: refused does not count', df_daily_count($cb), 2);
df_daily_inc($cb, -1);   // refund, as ask.php does on a failed call
check('capped: slot free after refund', df_daily_inc_capped($cb, 2), true);
check('capped: cap 0 = uncapped', df_daily_inc_capped($cb, 0), true);
check('capped: uncapped still counts', df_daily_count($cb), 3);
// concurrency: 16 processes race for 5 slots; exactly 5 may win
if (function_exists('proc_open')) {
    $cc = 'capconc' . getmypid();
    // Child diagnostics go to stderr, never stdout: a stray warning on stdout
    // (php.ini display_errors differs per host, e.g. CI) could hold a "Y" and
    // skew the count. stdout must be exactly one Y or N per child.
    $code = 'ini_set("display_errors", "stderr");'
          . 'require ' . var_export(__DIR__ . '/../public/lib.php', true) . ';'
          . '$GLOBALS["DF_CFG"]["cache_dir"] = ' . var_export($tmpCache, true) . ';'
          . 'usleep(200000 - (int)(fmod(microtime(true), 0.2) * 1e6));'
          . 'echo df_daily_inc_capped(' . var_export($cc, true) . ', 5) ? "Y" : "N";';
    $procs = []; $pipes = [];
    for ($i = 0; $i < 16; $i++) {
        $pr = proc_open([PHP_BINARY, '-r', $code], [1 => ['pipe', 'w']], $pp);
        if (!is_resource($pr)) continue;
        $procs[$i] = $pr;
        $pipes[$i] = $pp[1];
    }
    $out = '';
    foreach ($procs as $i => $pr) { $out .= stream_get_contents($pipes[$i]); fclose($pipes[$i]); proc_close($pr); }
    check('capped race: all 16 children answered Y/N', preg_match('/^[YN]{16}$/', $out) === 1 ? true : $out, true);
    check('capped race: exactly 5 winners', substr_count($out, 'Y'), 5);
    check('capped race: counter at cap', df_daily_count($cc), 5);
}

// --- hourly capped counter + FTP hourly budget (added 2026-11-08) -----------
$hb = 'hcaptest' . getmypid();
$t0 = gmmktime(13, 59, 58, 11, 8, 2026);          // 2026-11-08 13:59:58 UTC
check('hourly file name carries UTC hour', basename(df_hourly_file($hb, $t0)), 'hourly_' . $hb . '_2026110813');
check('hourly: 1st under cap', df_hourly_inc_capped($hb, 2, $t0), true);
check('hourly: 2nd reaches cap', df_hourly_inc_capped($hb, 2, $t0), true);
check('hourly: 3rd refused', df_hourly_inc_capped($hb, 2, $t0), false);
check('hourly: refused does not count', df_hourly_count($hb, $t0), 2);
check('hourly: rollover to next hour resets', df_hourly_inc_capped($hb, 2, $t0 + 2), true);
check('hourly: new hour count', df_hourly_count($hb, $t0 + 2), 1);
check('hourly: old hour untouched', df_hourly_count($hb, $t0), 2);
check('hourly: cap 0 = off', df_hourly_inc_capped($hb, 0, $t0), true);
check('hourly: cap 0 still counts', df_hourly_count($hb, $t0), 3);
check('hourly: GC treats hourly files as short-lived', strpos(basename(df_hourly_file($hb, $t0)), 'daily_') === 0, false);
check('retry-after: 2s before the hour', df_secs_to_next_hour($t0), 2);
check('retry-after: exactly on the hour = full hour', df_secs_to_next_hour($t0 + 2), 3600);
check('example config: ftp_hourly_cap default', df_cfg('ftp_hourly_cap'), 200);
$fc0 = df_daily_count('ftpcapped');
$GLOBALS['DF_CFG']['ftp_hourly_cap'] = 1;
$tf = gmmktime(3, 0, 0, 1, 2, 2001);              // an hour no other check uses
check('ftp budget: 1st fetch allowed', df_ftp_budget_ok($tf), true);
check('ftp budget: 2nd refused at cap 1', df_ftp_budget_ok($tf), false);
check('ftp budget: refusal bumps ftpcapped', df_daily_count('ftpcapped'), $fc0 + 1);
check('ftp budget: ftpcapped is an aggregate daily file', basename(df_daily_file('ftpcapped')), 'daily_ftpcapped_' . gmdate('Ymd'));
$GLOBALS['DF_CFG']['ftp_hourly_cap'] = 0;
check('ftp budget: cap 0 = off', df_ftp_budget_ok($tf), true);
check('ftp budget: off does not bump ftpcapped', df_daily_count('ftpcapped'), $fc0 + 1);
unset($GLOBALS['DF_CFG']['ftp_hourly_cap']);
check('example config: map_tile_hourly_cap default', df_cfg('map_tile_hourly_cap'), 300);
$tm = gmmktime(4, 0, 0, 1, 2, 2001);              // an hour no other check uses
$GLOBALS['DF_CFG']['map_tile_hourly_cap'] = 2;
check('map tile budget: 1st fetch allowed', df_map_tile_budget_ok($tm), true);
check('map tile budget: 2nd fetch allowed', df_map_tile_budget_ok($tm), true);
check('map tile budget: 3rd refused at cap 2', df_map_tile_budget_ok($tm), false);
check('map tile budget: refused does not count', df_hourly_count('maptile', $tm), 2);
check('map tile budget: next hour resets', df_map_tile_budget_ok($tm + 3600), true);
check('map tile budget: separate from ftp budget', df_hourly_count('ftp', $tm), 0);
$GLOBALS['DF_CFG']['map_tile_hourly_cap'] = 0;
check('map tile budget: cap 0 = off', df_map_tile_budget_ok($tm), true);
unset($GLOBALS['DF_CFG']['map_tile_hourly_cap']);
check('about lists ftp hourly cap', strpos(about_html([]), 'at most 200 FTP fetches') !== false, true);
check('about omits ftp cap when off', strpos(about_html(['ftp_hourly_cap' => 0]), 'FTP fetches (directory') !== false, false);
if (function_exists('proc_open')) {
    // concurrency: 16 processes race for 5 units of the same hour
    $hc = 'hcapconc' . getmypid();
    $code = 'ini_set("display_errors", "stderr");'
          . 'require ' . var_export(__DIR__ . '/../public/lib.php', true) . ';'
          . '$GLOBALS["DF_CFG"]["cache_dir"] = ' . var_export($tmpCache, true) . ';'
          . 'usleep(200000 - (int)(fmod(microtime(true), 0.2) * 1e6));'
          . 'echo df_hourly_inc_capped(' . var_export($hc, true) . ', 5, ' . $t0 . ') ? "Y" : "N";';
    $procs = []; $pipes = [];
    for ($i = 0; $i < 16; $i++) {
        $pr = proc_open([PHP_BINARY, '-r', $code], [1 => ['pipe', 'w']], $pp);
        if (!is_resource($pr)) continue;
        $procs[$i] = $pr;
        $pipes[$i] = $pp[1];
    }
    $out = '';
    foreach ($procs as $i => $pr) { $out .= stream_get_contents($pipes[$i]); fclose($pipes[$i]); proc_close($pr); }
    check('hourly race: all 16 children answered Y/N', preg_match('/^[YN]{16}$/', $out) === 1 ? true : $out, true);
    check('hourly race: exactly 5 winners', substr_count($out, 'Y'), 5);
    check('hourly race: counter at cap', df_hourly_count($hc, $t0), 5);
}
// ftp.php run as a page script with this hour's budget already spent: an IP
// literal (no DNS) passes validation, then the cap must answer 503 before any
// outbound connection -- for a listing and for a file. Prints the status code.
function ftp_capped_cli(string $url): string {
    $code = '$GLOBALS["argv"] = [];'
          . 'ini_set("display_errors", "stderr");'
          . 'require ' . var_export(__DIR__ . '/../public/lib.php', true) . ';'
          . '$GLOBALS["DF_CFG"]["cache_dir"] = ' . var_export($GLOBALS['tmpCache'], true) . ';'
          . '$GLOBALS["DF_CFG"]["ftp_hourly_cap"] = 1;'
          . 'df_hourly_inc_capped("ftp", 1);'                 // spend the hour (no-op if already spent)
          . '$_GET = ["url" => ' . var_export($url, true) . '];'
          . '$_COOKIE = ["df_pob" => df_pob_token()];'
          . 'register_shutdown_function(function () { echo "\nCODE=" . http_response_code(); });'
          . '$src = (string)file_get_contents(' . var_export(__DIR__ . '/../public/ftp.php', true) . ');'
          . '$src = preg_replace("/^require __DIR__ \\\\. \'\\\\/lib\\\\.php\';$/m", "", $src, 1);'
          . 'eval("?>" . $src);';
    return (string)shell_exec(escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg($code) . ' 2>/dev/null');
}
$fcBefore = df_daily_count('ftpcapped');
$fd = ftp_capped_cli('ftp://192.0.43.10/pub/');
check('ftp capped listing: 503', strpos($fd, "\nCODE=503") !== false, true);
check('ftp capped listing: busy page', strpos($fd, 'FTP gateway is busy') !== false, true);
check('ftp capped listing: no listing attempted', strpos($fd, 'Could not list') === false, true);
$ff = ftp_capped_cli('ftp://192.0.43.10/pub/file.zip');
check('ftp capped file: 503', strpos($ff, "\nCODE=503") !== false, true);
check('ftp capped file: busy page', strpos($ff, 'FTP gateway is busy') !== false, true);
check('ftp capped: both refusals counted', df_daily_count('ftpcapped'), $fcBefore + 2);

// map.php's GIF stitch run as a page script with this hour's OSM tile budget
// already spent: one tile (z2 1/1) is cached (solid red), the other three are
// not. The map must still be served from the cached tile, leave the rest grey
// (no outbound fetch is reserved or attempted), not cache the holey map, and
// bump the aggregate daily 'mapcapped' counter once. Prints the GIF base64.
function map_capped_cli(): string {
    $code = '$GLOBALS["argv"] = [];'
          . 'ini_set("display_errors", "stderr");'
          . 'require ' . var_export(__DIR__ . '/../public/lib.php', true) . ';'
          . '$GLOBALS["DF_CFG"]["cache_dir"] = ' . var_export($GLOBALS['tmpCache'], true) . ';'
          . '$GLOBALS["DF_CFG"]["map_tile_hourly_cap"] = 1;'
          . 'df_hourly_inc_capped("maptile", 1);'             // spend the hour
          . '$t = imagecreatetruecolor(256, 256); imagefill($t, 0, 0, imagecolorallocate($t, 255, 0, 0));'
          . 'ob_start(); imagepng($t); df_cache_put("tile:2:1:1", ob_get_clean());'
          . '$_GET = ["gif" => "1", "lat" => "0", "lon" => "0", "z" => "2"];'
          . '$_COOKIE = ["df_pob" => df_pob_token()];'
          . 'ob_start(function ($b) { return base64_encode($b); });'
          . '$src = (string)file_get_contents(' . var_export(__DIR__ . '/../public/map.php', true) . ');'
          . '$src = preg_replace("/^require __DIR__ \\\\. \'\\\\/lib\\\\.php\';$/m", "", $src, 1);'
          . 'eval("?>" . $src);';
    return (string)shell_exec(escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg($code) . ' 2>/dev/null');
}
$mdBefore = df_daily_count('maptile');
$mcBefore = df_daily_count('mapcapped');
$mtBefore = df_hourly_count('maptile');
$mg = base64_decode(map_capped_cli(), true);
check('map capped: GIF still served', is_string($mg) && strncmp($mg, 'GIF8', 4) === 0, true);
$mi = is_string($mg) ? @imagecreatefromstring($mg) : false;
if ($mi !== false) {
    $rgb = function (int $x, int $y) use ($mi): array {
        $c = imagecolorsforindex($mi, imagecolorat($mi, $x, $y));
        return [$c['red'], $c['green'], $c['blue']];
    };
    // GIF palette quantisation moves colours a few levels: compare within 8
    $near = function (array $a, array $b): bool {
        foreach ($a as $i => $v) if (abs($v - $b[$i]) > 8) return false;
        return true;
    };
    check('map capped: cached tile drawn', $near($rgb(200, 100), [255, 0, 0]) ? true : $rgb(200, 100), true);
    check('map capped: uncached tile left grey', $near($rgb(300, 250), [221, 221, 221]) ? true : $rgb(300, 250), true);
} else {
    check('map capped: GIF decodes', false, true);
}
check('map capped: counted once in mapcapped', df_daily_count('mapcapped'), $mcBefore + 1);
check('map capped: mapcapped is an aggregate daily file', basename(df_daily_file('mapcapped')), 'daily_mapcapped_' . gmdate('Ymd'));
check('map capped: no tile fetch reserved past the cap', df_hourly_count('maptile'), max(1, $mtBefore));
check('map capped: no fetch added to the daily maptile total', df_daily_count('maptile'), $mdBefore);
check('map capped: holey map not cached', df_cache_get('map2:color:2:0:0', 604800), null);

// --- reader: site-wide hourly fetch budget (added 2026-11-12) -----------------
check('example config: read_hourly_cap default', df_cfg('read_hourly_cap'), 300);
$rc0 = df_daily_count('readcapped');
$tr = gmmktime(6, 0, 0, 1, 2, 2001);              // an hour no other check uses (map uses 04 and 05)
$GLOBALS['DF_CFG']['read_hourly_cap'] = 1;
check('read budget: 1st fetch allowed', df_read_budget_ok($tr), true);
check('read budget: 2nd refused at cap 1', df_read_budget_ok($tr), false);
check('read budget: refusal bumps readcapped', df_daily_count('readcapped'), $rc0 + 1);
check('read budget: separate from ftp and map budgets', [df_hourly_count('ftp', $tr), df_hourly_count('maptile', $tr)], [0, 0]);
$GLOBALS['DF_CFG']['read_hourly_cap'] = 0;
check('read budget: cap 0 = off', df_read_budget_ok($tr), true);
check('read budget: off does not bump readcapped', df_daily_count('readcapped'), $rc0 + 1);
unset($GLOBALS['DF_CFG']['read_hourly_cap']);
$ru = 'https://example.invalid/read-cap-' . getmypid();
check('read cached: live miss', df_read_cached($ru), false);
df_cache_put('raw:' . $ru, serialize(['status' => 200, 'ctype' => 'text/html', 'body' => '<p>x</p>', 'url' => $ru]));
check('read cached: live hit (http_get_cached key)', df_read_cached($ru), true);
check('read cached: Wayback is a separate key', df_read_cached($ru, '20010601000000'), false);
df_cache_put('wb:20010601000000:' . $ru, serialize(['status' => 200, 'ctype' => 'text/html', 'body' => '<p>x</p>']));
check('read cached: Wayback hit (df_wayback_get key)', df_read_cached($ru, '20010601000000'), true);
// read.php run as a page script with this hour's budget spent: an uncached URL
// gets the 503 busy page before any fetch; a cached one is still served.
function read_capped_cli(string $url, string $year = ''): string {
    $get = ['url' => $url] + ($year !== '' ? ['year' => $year] : []);
    $code = '$GLOBALS["argv"] = [];'
          . 'ini_set("display_errors", "stderr");'
          . 'require ' . var_export(__DIR__ . '/../public/lib.php', true) . ';'
          . '$GLOBALS["DF_CFG"]["cache_dir"] = ' . var_export($GLOBALS['tmpCache'], true) . ';'
          . '$GLOBALS["DF_CFG"]["read_hourly_cap"] = 1;'
          . 'df_hourly_inc_capped("read", 1);'                 // spend the hour
          . '$_GET = ' . var_export($get, true) . ';'
          . '$_COOKIE = ["df_pob" => df_pob_token()];'
          . 'register_shutdown_function(function () { echo "\nCODE=" . http_response_code(); });'
          . '$src = (string)file_get_contents(' . var_export(__DIR__ . '/../public/read.php', true) . ');'
          . '$src = preg_replace("/^require __DIR__ \\\\. \'\\\\/lib\\\\.php\';$/m", "", $src, 1);'
          . 'eval("?>" . $src);';
    return (string)shell_exec(escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg($code) . ' 2>/dev/null');
}
$rcBefore = df_daily_count('readcapped');
$rmiss = read_capped_cli('https://example.invalid/read-cap-miss-' . getmypid());
check('read capped miss: 503', strpos($rmiss, "\nCODE=503") !== false, true);
check('read capped miss: busy page', strpos($rmiss, 'The reader is busy') !== false, true);
check('read capped miss: no fetch attempted', strpos($rmiss, 'Could not load') === false, true);
check('read capped miss: refusal counted', df_daily_count('readcapped'), $rcBefore + 1);
$rart = 'https://example.invalid/read-cap-hit-' . getmypid();
df_cache_put('raw:' . $rart, serialize(['status' => 200, 'ctype' => 'text/html', 'url' => $rart,
    'body' => '<html><head><title>Cached Story</title></head><body><article><p>'
            . str_repeat('A cached paragraph that is long enough to read. ', 40) . '</p></article></body></html>']));
$rhit = read_capped_cli($rart);
check('read capped hit: served, not 503', strpos($rhit, "\nCODE=503") === false && strpos($rhit, 'The reader is busy') === false, true);
check('read capped hit: cached page rendered', strpos($rhit, 'A cached paragraph') !== false, true);
check('read capped hit: not counted as a refusal', df_daily_count('readcapped'), $rcBefore + 1);
$rwb = read_capped_cli($rart, '2001');
check('read capped Wayback miss: 503 (live copy cached does not count)', strpos($rwb, "\nCODE=503") !== false, true);

// --- search: hourly DDG budget + block backoff (added 2026-11-12) -------------
check('example config: search_hourly_cap default', df_cfg('search_hourly_cap'), 200);
$sc0 = df_daily_count('searchcapped');
$tsr = gmmktime(7, 0, 0, 1, 2, 2001);             // an hour no other check uses
$GLOBALS['DF_CFG']['search_hourly_cap'] = 1;
check('search budget: 1st fetch allowed', df_search_budget_ok($tsr), true);
check('search budget: 2nd refused at cap 1', df_search_budget_ok($tsr), false);
check('search budget: refusal bumps searchcapped', df_daily_count('searchcapped'), $sc0 + 1);
$GLOBALS['DF_CFG']['search_hourly_cap'] = 0;
check('search budget: cap 0 = off', df_search_budget_ok($tsr), true);
unset($GLOBALS['DF_CFG']['search_hourly_cap']);
@unlink(df_ddg_backoff_file('html'));
$tb = 1000000000;
check('ddg backoff: none at start', df_ddg_backoff_remaining('html', $tb), 0);
check('ddg backoff: 1st block = 60 s', df_ddg_backoff_hit('html', $tb), 60);
check('ddg backoff: remaining counts down', df_ddg_backoff_remaining('html', $tb + 20), 40);
check('ddg backoff: per endpoint (lite unaffected)', df_ddg_backoff_remaining('lite', $tb + 20), 0);
check('ddg backoff: a block during the backoff does not escalate', df_ddg_backoff_hit('html', $tb + 20), 40);
check('ddg backoff: still level 1', df_ddg_backoff_state('html')['level'], 1);
check('ddg backoff: over after 60 s', df_ddg_backoff_remaining('html', $tb + 60), 0);
check('ddg backoff: blocked again soon after = 5 min', df_ddg_backoff_hit('html', $tb + 70), 300);
check('ddg backoff: and again = 15 min', df_ddg_backoff_hit('html', $tb + 70 + 300 + 5), 900);
check('ddg backoff: stays at 15 min', df_ddg_backoff_hit('html', $tb + 70 + 300 + 5 + 900 + 5), 900);
$tq = $tb + 70 + 300 + 5 + 900 + 5 + 900 + DF_DDG_BACKOFF_RESET;   // quiet for the reset window
check('ddg backoff: a block after a quiet spell starts over at 60 s', df_ddg_backoff_hit('html', $tq), 60);
check('ddg backoff: state file holds only until/level', array_keys((array)json_decode((string)@file_get_contents(df_ddg_backoff_file('html')), true)), ['until', 'level']);
check('ddg backoff: endpoint name sanitised', basename(df_ddg_backoff_file('../li te')), 'ddg_backoff_lite');
df_ddg_backoff_clear('html');
check('ddg backoff: clear drops the state', [df_ddg_backoff_remaining('html', $tq), df_ddg_backoff_state('html')['level']], [0, 0]);
df_ddg_backoff_clear('html');
check('ddg backoff: clear with no state is a no-op', is_file(df_ddg_backoff_file('html')), false);
check('ddg is_block: 202', df_ddg_is_block(['status' => 202, 'body' => '']), true);
check('ddg is_block: 429', df_ddg_is_block(['status' => 429, 'body' => '']), true);
check('ddg is_block: anomaly markup on a 200', df_ddg_is_block(['status' => 200, 'body' => '<div class="anomaly-modal">']), true);
check('ddg is_block: plain 200', df_ddg_is_block(['status' => 200, 'body' => '{"translated":"x"}']), false);
check('ddg is_block: 400 (stale token) is not a block', df_ddg_is_block(['status' => 400, 'body' => '']), false);
check('ddg is_block: network failure is not a block', df_ddg_is_block(null), false);
// index.php run as a page script with an uncached query. $setup runs first
// (in the child). Prints the page then "CODE=<status>". Every DDG answer the
// page could fetch is either seeded into the cache or excluded by a backoff,
// so these runs never touch the network.
function search_cli(string $q, string $setup): string {
    $code = '$GLOBALS["argv"] = [];'
          . 'ini_set("display_errors", "stderr");'
          . 'require ' . var_export(__DIR__ . '/../public/lib.php', true) . ';'
          . '$GLOBALS["DF_CFG"]["cache_dir"] = ' . var_export($GLOBALS['tmpCache'], true) . ';'
          . $setup
          . '$_GET = ["q" => ' . var_export($q, true) . '];'
          . 'register_shutdown_function(function () { echo "\nCODE=" . http_response_code(); });'
          . '$src = (string)file_get_contents(' . var_export(__DIR__ . '/../public/index.php', true) . ');'
          . '$src = preg_replace("/^require __DIR__ \\\\. \'\\\\/lib\\\\.php\';$/m", "", $src, 1);'
          . 'eval("?>" . $src);';
    return (string)shell_exec(escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg($code) . ' 2>/dev/null');
}
function seed_ddg(string $url, int $status, string $fixture): string {
    return 'df_cache_put(' . var_export('raw:' . $url, true) . ', serialize(["status" => ' . $status
         . ', "ctype" => "text/html", "url" => ' . var_export($url, true)
         . ', "body" => (string)file_get_contents(' . var_export(__DIR__ . '/fixtures/' . $fixture, true) . ')]));';
}
function reset_ddg_state(): void {
    df_ddg_backoff_clear('html'); df_ddg_backoff_clear('lite');
}
$sn = 0;
$sq = function () use (&$sn) { return 'duckfind backoff test ' . getmypid() . ' ' . (++$sn); };
$hurl = function (string $q) { return 'https://html.duckduckgo.com/html/?q=' . urlencode($q); };
$lurl = function (string $q) { return 'https://lite.duckduckgo.com/lite/?q=' . urlencode($q); };
// (a) both endpoints backing off: 503, no fetch, no budget unit
reset_ddg_state(); df_ddg_backoff_hit('html'); df_ddg_backoff_hit('lite');
$bo0 = df_daily_count('ddgbackoff'); $sh0 = df_hourly_count('search');
$sa = search_cli($sq(), '');
check('search, both backing off: 503', strpos($sa, "\nCODE=503") !== false, true);
check('search, both backing off: unavailable page', strpos($sa, 'Search is temporarily unavailable') !== false, true);
check('search, both backing off: no DDG fetch reserved', df_hourly_count('search'), $sh0);
check('search, both backing off: ddgbackoff counted', df_daily_count('ddgbackoff'), $bo0 + 1);
// (b) hourly budget spent: 503 search busy
reset_ddg_state();
$sc1 = df_daily_count('searchcapped');
$sb = search_cli($sq(), '$GLOBALS["DF_CFG"]["search_hourly_cap"] = 1; df_hourly_inc_capped("search", 1);');
check('search hourly cap: 503', strpos($sb, "\nCODE=503") !== false, true);
check('search hourly cap: busy page', strpos($sb, 'Search is busy') !== false, true);
check('search hourly cap: searchcapped counted', df_daily_count('searchcapped'), $sc1 + 1);
// (c) html answers with the real 202 challenge: html backs off, lite IS tried
// (here answered from the cache with real lite results) and serves the page
reset_ddg_state();
$q3 = $sq(); $lt0 = df_daily_count('ddglite');
$sc = search_cli($q3, seed_ddg($hurl($q3), 202, 'ddg-html-challenge.html') . seed_ddg($lurl($q3), 200, 'ddg-lite-results.html'));
check('html blocked: page served from lite', [strpos($sc, "\nCODE=503") === false, strpos($sc, '<ol start="1">') !== false], [true, true]);
check('html blocked: ddglite counted', df_daily_count('ddglite'), $lt0 + 1);
check('html blocked: html backs off, lite does not', [df_ddg_backoff_state('html')['level'], df_ddg_backoff_remaining('lite')], [1, 0]);
check('html blocked: challenge not left in the cache', df_cache_get('raw:' . $hurl($q3), 600), null);
// (d) html backing off: html is not requested at all, lite answers
$q4 = $sq(); $sh4 = df_hourly_count('search');
$sd = search_cli($q4, seed_ddg($lurl($q4), 200, 'ddg-lite-results.html'));
check('html backing off: lite serves the page', strpos($sd, '<ol start="1">') !== false, true);
check('html backing off: no html request (no unit reserved, nothing cached)', [df_hourly_count('search'), df_cache_get('raw:' . $hurl($q4), 600)], [$sh4, null]);
// (e) html backing off and lite answers with a block: lite backs off, page says unavailable
$q5 = $sq(); $lf5 = df_daily_count('ddglitefail');
$se = search_cli($q5, seed_ddg($lurl($q5), 202, 'ddg-html-challenge.html'));
check('lite blocked: unavailable message', strpos($se, 'Search is temporarily unavailable') !== false, true);
check('lite blocked: lite backs off', df_ddg_backoff_state('lite')['level'], 1);
check('lite blocked: ddglitefail counted', df_daily_count('ddglitefail'), $lf5 + 1);
// (f) a readable lite answer clears lite's backoff
df_ddg_backoff_clear('lite'); df_ddg_backoff_hit('lite', time() - 61);   // expired lite backoff, level 1
$q6 = $sq();
search_cli($q6, seed_ddg($lurl($q6), 200, 'ddg-lite-results.html'));
check('lite ok: clears its backoff state', is_file(df_ddg_backoff_file('lite')), false);
reset_ddg_state();

// --- search fallback: Brave Search API (added 2026-11-12) --------------------
// No real Brave response is captured yet (no key): the JSON below follows the
// shape in Brave's web-search docs (web.results[] {title, url, description}).
// Replace with a captured fixture once the key exists.
check('example config: brave off by default (no key)', [df_cfg('brave_api_key'), df_brave_enabled()], ['', false]);
check('example config: brave_daily_cap default', df_cfg('brave_daily_cap'), 100);
$braveJson = json_encode(['type' => 'search', 'query' => ['original' => 'retro mac'],
    'web' => ['type' => 'search', 'results' => [
        ['title' => 'Classic <strong>Mac</strong> Museum', 'url' => 'https://example.org/mac',
         'description' => 'All about the <strong>classic</strong> Mac &amp; its software.'],
        ['title' => 'Bad scheme', 'url' => 'javascript:alert(1)', 'description' => 'x'],
        ['title' => '', 'url' => 'http://example.net/', 'description' => ''],
    ]]]);
check('brave parse: results mapped, markup stripped, entities decoded', df_brave_parse($braveJson), [
    ['title' => 'Classic Mac Museum', 'url' => 'https://example.org/mac', 'snippet' => 'All about the classic Mac & its software.'],
    ['title' => 'http://example.net/', 'url' => 'http://example.net/', 'snippet' => ''],
]);
check('brave parse: no web block = genuine no results', df_brave_parse('{"type":"search","query":{"original":"x"}}'), []);
check('brave parse: not JSON = failure', df_brave_parse('<html>nope</html>'), null);
check('brave parse: error object = failure', df_brave_parse('{"type":"ErrorResponse","error":{"code":"x"}}'), null);
// df_brave_search through the test seam (never the network)
$GLOBALS['DF_CFG']['brave_api_key'] = 'test-key-not-real';
$braveCalls = [];
$GLOBALS['DF_TEST_BRAVE'] = function (string $url, array $h) use (&$braveCalls, $braveJson) {
    $braveCalls[] = [$url, $h];
    return ['status' => 200, 'ctype' => 'application/json', 'body' => $braveJson, 'url' => $url];
};
df_ddg_backoff_clear('brave');
check('brave search: results', count(df_brave_search('retro mac', 20) ?? []), 2);
check('brave search: key sent as a header, not in the URL',
      [strpos($braveCalls[0][0], 'test-key') === false, in_array('X-Subscription-Token: test-key-not-real', $braveCalls[0][1], true)], [true, true]);
check('brave search: DDG offset 20 -> Brave page 2, count 10', strpos($braveCalls[0][0], '&count=10&offset=2') !== false, true);
check('brave search: offset capped at page 9', strpos((df_brave_search('x', 500) !== null ? end($braveCalls)[0] : ''), '&offset=9') !== false, true);
$GLOBALS['DF_TEST_BRAVE'] = function (string $url, array $h) { return ['status' => 429, 'ctype' => 'application/json', 'body' => '{}', 'url' => $url]; };
check('brave search: 429 = failure', df_brave_search('x'), null);
check('brave search: 429 backs the brave endpoint off', df_ddg_backoff_state('brave')['level'], 1);
df_ddg_backoff_clear('brave');
$GLOBALS['DF_TEST_BRAVE'] = function (string $url, array $h) { return ['status' => 500, 'ctype' => 'text/html', 'body' => '', 'url' => $url]; };
check('brave search: 5xx = failure, no backoff', [df_brave_search('x'), is_file(df_ddg_backoff_file('brave'))], [null, false]);
unset($GLOBALS['DF_TEST_BRAVE']);
check('brave enabled: key + cap', df_brave_enabled(), true);
$GLOBALS['DF_CFG']['brave_daily_cap'] = 0;
check('brave enabled: cap 0 = off', df_brave_enabled(), false);
unset($GLOBALS['DF_CFG']['brave_daily_cap'], $GLOBALS['DF_CFG']['brave_api_key']);
// index.php: both DDG endpoints backing off, Brave configured (stubbed in the
// child). Brave serves the page, counts once, takes an hourly unit, caches nothing.
$braveStub = '$GLOBALS["DF_CFG"]["brave_api_key"] = "test-key-not-real";'
           . '$GLOBALS["DF_TEST_BRAVE"] = function ($u, $h) { return ["status" => 200, "ctype" => "application/json", "url" => $u, "body" => '
           . var_export($braveJson, true) . ']; };';
reset_ddg_state(); df_ddg_backoff_clear('brave'); df_ddg_backoff_hit('html'); df_ddg_backoff_hit('lite');
$q7 = $sq(); $bv0 = df_daily_count('brave'); $sh7 = df_hourly_count('search'); $bo7 = df_daily_count('ddgbackoff');
$s7 = search_cli($q7, $braveStub);
check('brave fallback: page served (not 503)', strpos($s7, "\nCODE=503") === false, true);
check('brave fallback: Brave results rendered', [strpos($s7, 'Classic Mac Museum') !== false, strpos($s7, 'these results are from Brave Search') !== false], [true, true]);
check('brave fallback: counted in brave and the hourly cap', [df_daily_count('brave'), df_hourly_count('search')], [$bv0 + 1, $sh7 + 1]);
check('brave fallback: not counted as ddgbackoff', df_daily_count('ddgbackoff'), $bo7);
check('brave fallback: nothing cached (no raw: entry for DDG endpoints)', [df_cache_get('raw:' . $hurl($q7), 600), df_cache_get('raw:' . $lurl($q7), 600)], [null, null]);
// Brave's own daily cap spent: no Brave request, the DDG-unavailable 503 as before
$s8 = search_cli($sq(), $braveStub . '$GLOBALS["DF_CFG"]["brave_daily_cap"] = 1; df_daily_inc_capped("brave", 1);'
    . '$GLOBALS["DF_TEST_BRAVE"] = function () { echo "BRAVE-CALLED"; return null; };');
check('brave cap spent: no Brave request', strpos($s8, 'BRAVE-CALLED') === false, true);
check('brave cap spent: 503 unavailable', [strpos($s8, "\nCODE=503") !== false, strpos($s8, 'Search is temporarily unavailable') !== false], [true, true]);
// no key configured: Brave never consulted (today's behaviour)
$s9 = search_cli($sq(), '$GLOBALS["DF_TEST_BRAVE"] = function () { echo "BRAVE-CALLED"; return null; };');
check('brave without a key: never called, 503 as before', [strpos($s9, 'BRAVE-CALLED') === false, strpos($s9, "\nCODE=503") !== false], [true, true]);
// Brave backing off (after a 429): not called
$s10 = search_cli($sq(), $braveStub . 'df_ddg_backoff_hit("brave");'
    . '$GLOBALS["DF_TEST_BRAVE"] = function () { echo "BRAVE-CALLED"; return null; };');
check('brave backing off: not called', strpos($s10, 'BRAVE-CALLED') === false, true);
reset_ddg_state(); df_ddg_backoff_clear('brave');

// --- reader pager links: rel=next / rel=prev (added 2026-11-08) ---------------
// Parsed exactly as extract_readable() parses a page.
function rel_pages(string $html): array {
    $d = new DOMDocument();
    libxml_use_internal_errors(true);
    $d->loadHTML('<?xml encoding="UTF-8" ?>' . $html);
    libxml_clear_errors();
    return df_rel_pages(new DOMXPath($d));
}
check('pager: middle page, <link> in head',
      rel_pages('<html><head><link rel="prev" href="/story?page=1"><link rel="next" href="/story?page=3"></head><body><p>x</p></body></html>'),
      ['next' => '/story?page=3', 'prev' => '/story?page=1']);
check('pager: page 1 has next only',
      rel_pages('<head><link rel="next" href="p2.html"></head><body><p>x</p></body>'),
      ['next' => 'p2.html', 'prev' => '']);
check('pager: last page has prev only, from <a rel>',
      rel_pages('<body><p>x</p><a rel="prev" href="p2.html">&lt; back</a></body>'),
      ['next' => '', 'prev' => 'p2.html']);
check('pager: rel=previous synonym',
      rel_pages('<body><a rel="previous" href="../1/">Previous</a></body>'),
      ['next' => '', 'prev' => '../1/']);
check('pager: href whitespace trimmed',
      rel_pages('<head><link rel="prev" href="  p1.html "></head>')['prev'], 'p1.html');
check('pager: first in document order wins',
      rel_pages('<head><link rel="prev" href="head-p1"></head><body><a rel="prev" href="body-p1">x</a></body>')['prev'], 'head-p1');
check('pager: none', rel_pages('<body><p>single page</p><a href="p2">page 2</a></body>'), ['next' => '', 'prev' => '']);
check('pager: no rel=prev on a non-link element', rel_pages('<body><div rel="prev" href="x">x</div></body>')['prev'], '');
check('pager: 1998 uppercase REL="NEXT"/LINK',
      rel_pages('<HTML><HEAD><LINK REL="PREV" HREF="p1.html"><LINK REL="NEXT" HREF="p3.html"></HEAD><BODY>x</BODY></HTML>'),
      ['next' => 'p3.html', 'prev' => 'p1.html']);
check('pager: mixed case Previous', rel_pages('<body><A REL="Previous" HREF="p1.html">back</A></body>')['prev'], 'p1.html');
check('pager: rel token list', rel_pages('<body><a rel="nofollow next" href="p2.html">more</a></body>')['next'], 'p2.html');
check('pager: no substring match', rel_pages('<body><a rel="nextpage prevent" href="x">x</a></body>'), ['next' => '', 'prev' => '']);
check('pager: relative prev absolutizes', absolutize('https://ex.com/story/2/', '../1/'), 'https://ex.com/story/1/');
check('page_head: head extra before </head>',
      strpos(page_head('t', true, '', '<link rel="prev" href="/read.php?url=x">' . "\n"), "<link rel=\"prev\" href=\"/read.php?url=x\">\n</head>") !== false, true);
check('page_head: no rel=prev by default', strpos(page_head('t', true), 'rel="prev"'), false);

// --- Wayback capture years (CDX) for the reader's era switcher (added 2026-11-08) ---
// Fixture: a real 2026-11-08 response for url=apple.com/&output=json&fl=timestamp
// &collapse=timestamp:4&filter=statuscode:200&limit=60, trimmed to 4 of 31 rows.
$cdxReal = "[[\"timestamp\"],\n[\"19961022105458\"],\n[\"19970404064352\"],\n"
         . "[\"19980509035420\"],\n[\"20260101000631\"]]";
check('cdx parse real rows', df_wayback_years_parse($cdxReal),
      [1996 => '19961022105458', 1997 => '19970404064352', 1998 => '19980509035420', 2026 => '20260101000631']);
check('cdx parse no captures', df_wayback_years_parse('[]'), []);            // real body for a never-captured URL
check('cdx parse header only', df_wayback_years_parse('[["timestamp"]]'), []);
check('cdx parse html error page', df_wayback_years_parse('<html><body>429 Too Many Requests</body></html>'), null);
check('cdx parse truncated', df_wayback_years_parse('[["timestamp"],["1996102210'), null);
check('cdx parse non-digit ts', df_wayback_years_parse('[["timestamp"],["latest"]]'), null);
check('cdx parse sorts + dedupes + pads',
      df_wayback_years_parse('[["20010101000000"],["1999"],["20010505000000"],["1985"]]'),
      [1999 => '19990000000000', 2001 => '20010101000000']);
check('cdx key drops scheme', df_wayback_years_key('https://apple.com/mac?a=1#top'), 'apple.com/mac?a=1');
check('cdx key http=https', df_wayback_years_key('http://apple.com/'), df_wayback_years_key('HTTPS://apple.com/'));
// cache round trip (json_encode turns the year keys into object keys and back)
$wbU = 'https://example.org/wb-test-' . getmypid();
check('wbyears unknown before fill', df_wayback_years_cached($wbU), null);
df_cache_put('wbyrs:' . df_wayback_years_key($wbU), json_encode(df_wayback_years_parse($cdxReal)));
check('wbyears cached round trip', df_wayback_years_cached($wbU), df_wayback_years_parse($cdxReal));
// fill short-circuits with no network: IA backoff set -> no query, nothing cached
$wbU2 = $wbU . '-b';
df_cache_put('wbyrs-backoff', '1');
df_wayback_years_fill($wbU2);
check('wbyears fill honours IA backoff', df_wayback_years_cached($wbU2), null);
df_cache_del('wbyrs-backoff');
df_cache_put('wbyrsfail:' . df_wayback_years_key($wbU2), '1');
df_wayback_years_fill($wbU2);
check('wbyears fill honours negative cache', df_wayback_years_cached($wbU2), null);
// switcher render: read.php run as a page script from a seeded cache, no network
function read_html(string $url, string $year = '', array $extra = []): string {
    $get = ['url' => $url] + ($year !== '' ? ['year' => $year] : []) + $extra;
    $code = '$GLOBALS["argv"] = [];'
          . 'require ' . var_export(__DIR__ . '/../public/lib.php', true) . ';'
          . '$GLOBALS["DF_CFG"]["cache_dir"] = ' . var_export($GLOBALS['tmpCache'], true) . ';'
          . '$_GET = ' . var_export($get, true) . ';'
          . '$_COOKIE = ["df_pob" => df_pob_token()];'
          . '$src = (string)file_get_contents(' . var_export(__DIR__ . '/../public/read.php', true) . ');'
          . '$src = preg_replace("/^require __DIR__ \\\\. \'\\\\/lib\\\\.php\';$/m", "", $src, 1);'
          . 'eval("?>" . $src);';
    return (string)shell_exec(escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg($code) . ' 2>&1');
}
$page = serialize(['body' => '<html><head><title>T</title></head><body><p>' . str_repeat('word ', 200)
                   . '</p></body></html>', 'ctype' => 'text/html', 'status' => 200, 'url' => $wbU]);
df_cache_put('raw:' . $wbU, $page);
df_cache_put('raw:' . $wbU2, $page);
df_cache_put('wb:19970404064352:' . $wbU, $page);
$wbBar = fn(string $h) => preg_match('#<font size="1">Wayback:.*?</font>#', $h, $m) ? $m[0] : '';
$bar = $wbBar(read_html($wbU));
check('switcher lists CDX years only', preg_match_all('#>\'(\d\d)</a>#', $bar, $mm) ? $mm[1] : [], ['96', '97', '98', '26']);
check('switcher links the real capture ts', strpos($bar, '&amp;year=19970404064352&amp;raw=0">\'97</a>') !== false, true);
check('switcher drops uncaptured fixed years', strpos($bar, "'02"), false);
$bar = $wbBar(read_html($wbU, '19970404064352'));
check('switcher bolds current era', strpos($bar, "<b>['97]</b>") !== false, true);
check('switcher live link in wayback mode', strpos($bar, '"><b>live</b></a>') !== false, true);
$bar = $wbBar(read_html($wbU2));
check('switcher falls back to fixed years on miss', preg_match_all('#>\'(\d\d)</a>#', $bar, $mm) ? $mm[1] : [],
      ['98', '02', '06', '10', '15', '20']);
df_cache_put('wbyrs:' . df_wayback_years_key($wbU2), '[]');
$bar = $wbBar(read_html($wbU2));
check('switcher says none when CDX has no captures', strpos($bar, '<i>no archived copies</i>') !== false
      && strpos($bar, '</a>') === false, true);
foreach (['wbyrs:' . df_wayback_years_key($wbU), 'wbyrs:' . df_wayback_years_key($wbU2),
          'wbyrsfail:' . df_wayback_years_key($wbU2), 'raw:' . $wbU, 'raw:' . $wbU2,
          'wb:19970404064352:' . $wbU, 'wbyrs-backoff'] as $k) {
    $cf = df_cache_path($k); @unlink($cf); @rmdir(dirname($cf));
}

// --- Wayback bar thinning + privacy gate on the CDX fill ----------------------
$wbAll = [];
for ($y = 1996; $y <= 2026; $y++) $wbAll[(string)$y] = $y . '0101000000';
$th = df_wayback_thin($wbAll, '', 12);
check('wb thin: 31 -> 12', count($th), 12);
check('wb thin: keeps first', (string)array_key_first($th), '1996');
check('wb thin: keeps last', (string)array_key_last($th), '2026');
check('wb thin: order + values kept', $th === array_intersect_key($wbAll, $th), true);
$ks = array_map('intval', array_keys($th)); $gaps = [];
for ($i = 1; $i < count($ks); $i++) $gaps[] = $ks[$i] - $ks[$i - 1];
check('wb thin: evenly spread (max gap <= 3)', max($gaps) <= 3, true);
$th2 = df_wayback_thin($wbAll, '2003', 12);
check('wb thin: keeps current era', isset($th2['2003']) && count($th2) === 12, true);
check('wb thin: short list untouched', df_wayback_thin(['1999' => 'a', '2005' => 'b'], '', 12), ['1999' => 'a', '2005' => 'b']);
// the post-response CDX fill must only run in Wayback mode (a live read never
// sends the URL to archive.org) -- source guard, since fastcgi_finish_request
// doesn't exist under the CLI
check('wb fill gated on DF_YEAR', strpos((string)file_get_contents(__DIR__ . '/../public/read.php'),
      "if (\$wbYears === null && DF_YEAR !== '' && function_exists('fastcgi_finish_request')) {") !== false, true);

// --- ASCII-art image mode ------------------------------------------------------
$asciiOnly = fn(string $a) => preg_match('/[^\x0A\x20-\x7E]/', $a) === 0;   // printable ASCII + \n only
$lines = fn(string $a) => explode("\n", $a);
// mode normalisers: pages accept ascii, the GIF renderers never see it
check('page mode ascii', df_page_img_mode('ascii'), 'ascii');
check('page mode ASCII', df_page_img_mode('ASCII'), 'ascii');
check('page mode gray kept', df_page_img_mode('gray'), 'gray');
check('page mode array-safe', df_page_img_mode(['ascii']), 'color');
check('gif mode ignores ascii', df_img_mode('ascii'), 'color');

// gradient, black (left) to white (right): 80x40 px at 40 cols
$g = imagecreatetruecolor(80, 40);
for ($x = 0; $x < 80; $x++) { $v = (int)round(255 * $x / 79); imageline($g, $x, 0, $x, 39, imagecolorallocate($g, $v, $v, $v)); }
$a = df_ascii_art($g, 40);
$L = $lines($a);
check('ascii gradient rows (2:1 aspect: 40/80*40*0.5)', count($L), 10);
check('ascii gradient width <= cols', max(array_map('strlen', $L)) <= 40, true);
check('ascii gradient dark side is dense', $L[0][0], '@');
check('ascii gradient white side is blank (trimmed)', strlen($L[0]) < 40 && strlen($L[0]) > 30, true);
$ramp = DF_ASCII_RAMP; $mono = true;
for ($i = 1; $i < strlen($L[0]); $i++) if (strpos($ramp, $L[0][$i]) > strpos($ramp, $L[0][$i - 1])) $mono = false;
check('ascii gradient density never rises left->right', $mono, true);
check('ascii gradient every row identical', count(array_unique($L)), 1);
check('ascii gradient ascii-only', $asciiOnly($a), true);

// auto-levels: a low-contrast photo (greys 100..160) still spans the whole
// ramp; a flat image is NOT stretched (half-alpha check below stays mid-ramp)
$lc = imagecreatetruecolor(80, 40);
for ($x = 0; $x < 80; $x++) { $v = 100 + (int)round(60 * $x / 79); imageline($lc, $x, 0, $x, 39, imagecolorallocate($lc, $v, $v, $v)); }
$lcl = $lines(df_ascii_art($lc, 40))[0];
check('ascii low-contrast stretched: dense end', $lcl[0], '@');
check('ascii low-contrast stretched: blank end', strlen($lcl) < 40, true);
$fl = imagecreatetruecolor(20, 20);
imagefill($fl, 0, 0, imagecolorallocate($fl, 128, 128, 128));
check('ascii flat grey not stretched', $lines(df_ascii_art($fl, 20))[0], str_repeat('=', 20));

// aspect correction: a square is half as many rows as columns; tall images cap
$sq = imagecreatetruecolor(100, 100);
check('ascii square 40 cols -> 20 rows', count($lines(df_ascii_art($sq, 40))), 20);
$tall = imagecreatetruecolor(40, 200);
$ta = $lines(df_ascii_art($tall, 40, false, DF_ASCII_RAMP, 40));
check('ascii tall capped at maxRows', count($ta), 40);
check('ascii tall narrowed to keep aspect (40/0.5*40/200 = 16)', strlen($ta[0]), 16);
$tiny = imagecreatetruecolor(10, 10);
check('ascii never upscales past pixel width', strlen($lines(df_ascii_art($tiny, 40))[0]), 10);

// black square on white: dense in the middle, blank around it
$bs = imagecreatetruecolor(40, 40);
imagefill($bs, 0, 0, imagecolorallocate($bs, 255, 255, 255));
imagefilledrectangle($bs, 10, 10, 29, 29, imagecolorallocate($bs, 0, 0, 0));
$before = imagecolorat($bs, 0, 0);
$B = $lines(df_ascii_art($bs, 20));
check('ascii square rows', count($B), 10);
check('ascii square top row blank', $B[0], '');
check('ascii square centre dense', substr($B[5], 5, 10), '@@@@@@@@@@');
check('ascii square left margin blank', substr($B[5], 0, 5), '     ');
check('ascii input image untouched', imagecolorat($bs, 0, 0) === $before && imagesx($bs) === 40, true);

// transparent PNG (round-tripped through real PNG bytes): fully transparent
// BLACK background must composite to white (blank), not read as black ink
$tp = imagecreatetruecolor(40, 40);
imagealphablending($tp, false); imagesavealpha($tp, true);
imagefilledrectangle($tp, 0, 0, 39, 39, imagecolorallocatealpha($tp, 0, 0, 0, 127));
imagefilledrectangle($tp, 10, 10, 29, 29, imagecolorallocatealpha($tp, 0, 0, 0, 0));
ob_start(); imagepng($tp); $png = ob_get_clean();
$tpi = imagecreatefromstring($png);
$T = $lines(df_ascii_art($tpi, 20));
check('ascii transparent bg is blank', $T[0] === '' && substr($T[5], 0, 5) === '     ', true);
check('ascii transparent opaque square dense', substr($T[5], 5, 10), '@@@@@@@@@@');
// half-transparent black over white = mid grey, mid-ramp
$hp = imagecreatetruecolor(8, 8);
imagealphablending($hp, false); imagesavealpha($hp, true);
imagefilledrectangle($hp, 0, 0, 7, 7, imagecolorallocatealpha($hp, 0, 0, 0, 64));
$hc = df_ascii_art($hp, 8)[0];
check('ascii half-alpha is mid-ramp', strpos(DF_ASCII_RAMP, $hc) >= 3 && strpos(DF_ASCII_RAMP, $hc) <= 6, true);
// dark theme: bright pixels are the ink, transparency composites on black
$wd = imagecreatetruecolor(40, 40);
imagealphablending($wd, false); imagesavealpha($wd, true);
imagefilledrectangle($wd, 0, 0, 39, 39, imagecolorallocatealpha($wd, 255, 255, 255, 127));
imagefilledrectangle($wd, 10, 10, 29, 29, imagecolorallocatealpha($wd, 255, 255, 255, 0));
$D = $lines(df_ascii_art($wd, 20, true));
check('ascii dark bg: white square dense', substr($D[5], 5, 10), '@@@@@@@@@@');
check('ascii dark bg: transparent blank', $D[0], '');
check('ascii dark bg inverts ramp', $lines(df_ascii_art($bs, 20, true))[0][0], '@');

// escaping + Latin-1/ASCII-only, even for a hostile custom ramp
$ea = df_ascii_art($g, 40, false, " <&\"'\u{00E9}\u{2588}");
check('ascii escapes <', strpos($ea, '&lt;') !== false && strpos($ea, '<') === false, true);
check('ascii escapes &', strpos($ea, '&amp;') !== false, true);
check('ascii escapes quotes', strpos($ea, '"') === false && strpos($ea, "'") === false, true);
check('ascii drops non-ASCII ramp chars', $asciiOnly($ea), true);
check('ascii too-short ramp falls back', df_ascii_art($bs, 20, false, "\u{2588}"), df_ascii_art($bs, 20));
foreach (['gradient' => $a, 'square' => implode("\n", $B), 'transparent' => implode("\n", $T)] as $nm => $out) {
    check("ascii $nm latin-1 safe", mb_check_encoding($out, 'ASCII'), true);
}

// anchor hoist + fallback text
check('hoist lifts art out of a link', df_ascii_hoist('<a href="/x">', '<pre>@@</pre> Caption'),
      '<pre>@@</pre><a href="/x">Caption</a>');
check('hoist image-only link gets [link]', df_ascii_hoist('<a href="/x">', '<pre>@@</pre><br>'),
      '<pre>@@</pre><a href="/x">[link]</a>');
check('hoist leaves plain links alone', df_ascii_hoist('<a href="/x">', 'text'), '<a href="/x">text</a>');
check('fallback escapes alt + links the gif', df_ascii_fallback('https://e.com/a b.png', 'A <b>'),
      '<a href="/img.php?url=https%3A%2F%2Fe.com%2Fa+b.png">[image: A &lt;b&gt;]</a>');
check('fallback inside a link is plain text', df_ascii_fallback('https://e.com/a.png', '', false), '[image]');

// inline path, offline: gate, cache, per-page cap
$GLOBALS['DF_CFG']['ascii_max_per_page'] = 2;
$_COOKIE = [];
$ak = fn(string $u) => 'ascii:' . DF_ASCII_COLS . ':l::' . $u;
check('inline rejects non-http', df_ascii_inline('file:///etc/passwd'), null);
// no df_pob cookie: an uncached image is NOT fetched (no imgfail entry is ever written)
check('inline gate: no cookie, no fetch', df_ascii_inline('http://127.0.0.1/gate.png'), null);
check('inline gate: nothing attempted', df_cache_get('imgfail:http://127.0.0.1/gate.png', 900), null);
df_cache_put($ak('https://e.com/1.png'), '<pre>11</pre>');
df_cache_put($ak('https://e.com/2.png'), '<pre>22</pre>');
df_cache_put($ak('https://e.com/3.png'), '<pre>33</pre>');
df_cache_put($ak('https://e.com/s.png'), '');
check('inline cache hit (ungated, like img.php)', df_ascii_inline('https://e.com/1.png'), '<pre>11</pre>');
check('inline cached spacer is empty, not counted', df_ascii_inline('https://e.com/s.png'), '');
check('inline second hit', df_ascii_inline('https://e.com/2.png'), '<pre>22</pre>');
check('inline per-page cap reached', df_ascii_inline('https://e.com/3.png'), null);
// with the cookie, an SSRF-blocked url goes through http_get's validation and fails
foreach (['1', '2', '3', 's'] as $n) { $cf = df_cache_path($ak("https://e.com/$n.png")); @unlink($cf); @rmdir(dirname($cf)); }
unset($GLOBALS['DF_CFG']['ascii_max_per_page']);
// cookieless vintage browser: same exemption as img.php, so it gets past the
// gate (counted in pobxlegacy) and the fetch is attempted -- SSRF-blocked here,
// so it fails (no imgfail entry: the inline path's shortened timeout skips it)
function ascii_child(string $ua, string $url): string {
    $code = '$GLOBALS["argv"] = [];'
          . 'require ' . var_export(__DIR__ . '/../public/lib.php', true) . ';'
          . '$GLOBALS["DF_CFG"]["cache_dir"] = ' . var_export($GLOBALS['tmpCache'], true) . ';'
          . '$_SERVER["HTTP_USER_AGENT"] = ' . var_export($ua, true) . '; $_COOKIE = [];'
          . 'var_export(df_ascii_inline(' . var_export($url, true) . '));';
    return (string)shell_exec(escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg($code) . ' 2>&1');
}
$x0 = df_daily_count('pobxlegacy');
check('inline gate: modern cookieless, no fetch', ascii_child('Mozilla/5.0 (X11) Firefox/120.0', 'http://127.0.0.1/modern.png'), 'NULL');
check('inline gate: modern cookieless, nothing attempted', df_cache_get('imgfail:http://127.0.0.1/modern.png', 900), null);
check('inline gate: modern cookieless not counted', df_daily_count('pobxlegacy'), $x0);
check('inline gate: legacy cookieless, blocked url still null', ascii_child('Lynx/2.8.9rel.1', 'http://127.0.0.1/legacy.png'), 'NULL');
check('inline gate: legacy cookieless passed the gate (counted once)', df_daily_count('pobxlegacy'), $x0 + 1);
check('inline gate: bot cookieless not exempted', ascii_child('Mozilla/4.0 (compatible; bingbot/2.0)', 'http://127.0.0.1/bot.png') === 'NULL'
      && df_daily_count('pobxlegacy') === $x0 + 1, true);

// feed/news rivers: ascii mode drops the thumbnail column (and never does the
// og:image lookups); gray still gets its thumbnails with im=gray
$riv = [['title' => 'T', 'link' => 'https://e.com/a', 'src' => 'S', 'img' => 'https://e.com/t.jpg']];
$_COOKIE = ['df_mode' => 'ascii'];
$rh = df_river($riv);
check('river ascii: no thumbnails', stripos($rh, '<img') === false && strpos($rh, 'width="96"') === false, true);
$_COOKIE = ['df_mode' => 'gray'];
check('river gray: thumbnail kept', strpos(df_river($riv), '&amp;w=88&amp;im=gray"') !== false, true);
$_COOKIE = [];

// read.php in ascii mode, from a seeded cache (no network): art inlined in
// place of <img>, art lifted out of links, failures -> [image: alt] links
$aU = 'https://ascii-test.invalid/article';
$aBody = '<html><head><title>Ascii T</title></head><body><article><p>' . str_repeat('word ', 200) . '</p>'
       . '<p><img src="https://ascii-test.invalid/a.png" alt="A cat"></p>'
       . '<p><a href="https://ascii-test.invalid/full"><img src="https://ascii-test.invalid/b.png" alt="xx"></a></p>'
       . '<p><img src="http://127.0.0.1/c.png" alt="Blocked one"></p>'
       . '<p>' . str_repeat('more ', 100) . '</p></article></body></html>';
df_cache_put('raw:' . $aU, serialize(['body' => $aBody, 'ctype' => 'text/html', 'status' => 200, 'url' => $aU]));
df_cache_put($ak('https://ascii-test.invalid/a.png'), "<pre>@@%%##\n..::--</pre>");
df_cache_put($ak('https://ascii-test.invalid/b.png'), '<pre>BBBB</pre>');
$ah = read_html($aU, '', ['im' => 'ascii']);
check('read ascii: art inlined', strpos($ah, "<pre>@@%%##\n..::--</pre>") !== false, true);
check('read ascii: no <img> at all', stripos($ah, '<img'), false);
check('read ascii: alt shown as caption', strpos($ah, '<i>A cat</i>') !== false, true);
check('read ascii: art hoisted out of link', (bool)preg_match('#<pre>BBBB</pre><a href="/read\.php\?url=[^"]*full[^"]*">\[link\]</a>#', $ah), true);
check('read ascii: blocked image -> fallback link', strpos($ah, '>[image: Blocked one]</a>') !== false, true);
check('read ascii: toolbar shows ascii active', strpos($ah, '<b>ascii</b>') !== false, true);
check('read ascii: links persist the mode', strpos($ah, '&amp;im=ascii') !== false, true);
check('read ascii: page ascii-only', $asciiOnly(str_replace(["\r", "\t"], '', $ah)), true);
$at = read_html($aU, '', ['im' => 'ascii', 'fmt' => 'txt']);
check('read ascii + plain text: no art, no fallback links', strpos($at, '@@%%##') === false
      && strpos($at, 'BBBB') === false && strpos($at, 'word word') !== false, true);
$ac = read_html($aU, '', ['im' => 'gray']);
check('read gray: unchanged <img> path', strpos($ac, '<img src="/img.php?url=https%3A%2F%2Fascii-test.invalid%2Fa.png&amp;im=gray"') !== false
      && strpos($ac, '<pre>') === false, true);
foreach (['raw:' . $aU, $ak('https://ascii-test.invalid/a.png'), $ak('https://ascii-test.invalid/b.png'),
          'imgfail:http://127.0.0.1/c.png'] as $k) {
    $cf = df_cache_path($k); @unlink($cf); @rmdir(dirname($cf));
}

// --- image negative cache is keyed by Wayback era ----------------------------
check('imgfail key: live unchanged', df_imgfail_key('https://e.com/i.png'), 'imgfail:https://e.com/i.png');
check('imgfail key: era', df_imgfail_key('https://e.com/i.png', '1998'), 'imgfail:1998:https://e.com/i.png');
// a failed live fetch (SSRF-blocked here, no network) blanks only the live copy
$ifU = 'http://127.0.0.1/era.png';
check('img load: live failure', df_img_load($ifU), null);
check('img load: live failure negative-cached', df_cache_get(df_imgfail_key($ifU), 900), '1');
check('img load: live failure does not blank a Wayback era', df_cache_get(df_imgfail_key($ifU, '1998'), 900), null);
// and an era's negative-cache entry short-circuits only that era (no fetch)
df_cache_put(df_imgfail_key($ifU, '2002'), '1');
check('img load: era negative cache honoured', df_img_load($ifU, '2002'), null);
foreach (['', '2002'] as $y) { $cf = df_cache_path(df_imgfail_key($ifU, $y)); @unlink($cf); @rmdir(dirname($cf)); }

// --- map lat/lon array params read as 0, not 1.0 -----------------------------
check('df_str array -> float 0', (float)df_str(['x']), 0.0);

// --- read.php extractor crashes (regression 2026-10-29: both were 500s) --------
// A page script's top-level functions exist from compile time, so run its
// no-URL landing branch (no network) and call into it from a shutdown function,
// which still runs after the page's own exit. Returns what $code echoes.
function page_fn_cli(string $page, string $code): string {
    $boot = 'ob_start(); register_shutdown_function(function () { ob_end_clean(); ' . $code . ' });'
          . ' require ' . var_export(__DIR__ . '/../public/' . $page, true) . ';';
    return trim((string)shell_exec(escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg($boot) . ' 2>&1'));
}
check('recipe: scalar @graph entries skipped', page_fn_cli('read.php',
    '$r = extract_recipe(\'<script type="application/ld+json">{"@graph":["x",null,{"@type":"Recipe",'
    . '"name":"Soup","recipeIngredient":["water"]}]}</script>\', "https://ex.com/"); echo $r[0] ?? "null";'),
    'Soup');
foreach (['<!DOCTYPE html>', '<!-- empty -->'] as $body) {
    check("reader: rootless body $body", page_fn_cli('read.php',
        'echo strip_tags(extract_readable(' . var_export($body, true) . ', "https://ex.com/")[1]), "|",'
        . ' strip_tags(render_original(' . var_export($body, true) . ', "https://ex.com/")[1]);'),
        '(no readable text found)|(no readable text found)');
}

// --- df_cacheable_response: shared by http_get_cached and df_wayback_get -------
// (2026-11-10: df_wayback_get cached any status < 400, so an empty 200 from the
// Archive was frozen in for a day (reader) or a week (images, PDFs).)
check('cacheable 200',        df_cacheable_response(['status' => 200, 'body' => 'x']), true);
check('cacheable 206',        df_cacheable_response(['status' => 206, 'body' => 'x']), true);
check('not cacheable null',   df_cacheable_response(null), false);
check('not cacheable 202',    df_cacheable_response(['status' => 202, 'body' => 'x']), false);
check('not cacheable empty',  df_cacheable_response(['status' => 200, 'body' => '']), false);
check('not cacheable 3xx',    df_cacheable_response(['status' => 302, 'body' => 'x']), false);
check('not cacheable 404',    df_cacheable_response(['status' => 404, 'body' => 'x']), false);
check('wayback uses the shared rule', strpos((string)file_get_contents(__DIR__ . '/../public/lib.php'),
    "if (df_cacheable_response(\$r)) df_cache_put(\$key, serialize(\$r));\n            return \$r;") !== false, true);

// --- dl.php / ftp.php: refuse a declared over-cap file before sending anything --
// (2026-11-10: a 150 MB file streamed 52 MB under a 200, then was cut off -- a
// corrupt download and no error page). Needs a live origin to exercise, so this
// only pins the guard in place; verified by hand against ftp.gnu.org.
foreach (['dl.php' => 'DL_MAX_BYTES', 'ftp.php' => 'FTP_MAX_BYTES'] as $pg => $capc) {
    check("$pg refuses declared over-cap size", strpos((string)file_get_contents(__DIR__ . '/../public/' . $pg),
        "curl_getinfo(\$ch, CURLINFO_CONTENT_LENGTH_DOWNLOAD) > $capc) return 0;") !== false, true);
}

echo "$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
