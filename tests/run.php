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
check('about lists ftp hourly cap', strpos(about_html([]), '200 FTP fetches (directory listings or files)') !== false, true);
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
          . '$GLOBALS["DF_CFG"]["captcha_enabled"] = false;'   // the plain busy page
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
          . '$GLOBALS["DF_CFG"]["captcha_enabled"] = false;'   // the plain busy page
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
$sb = search_cli($sq(), '$GLOBALS["DF_CFG"]["captcha_enabled"] = false; $GLOBALS["DF_CFG"]["search_hourly_cap"] = 1; df_hourly_inc_capped("search", 1);');
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

// --- over-cap captcha (added 2026-11-12) -----------------------------------
check('example config: captcha defaults', [df_cfg('captcha_enabled'), df_cfg('captcha_token_budget'), df_cfg('rate')['captcha'] ?? null], [true, 30, [20, 60]]);
$capCfg = [df_cfg('captcha_enabled'), df_cfg('captcha_token_budget')];
$tc = 1100000000;
$ch = '1100000000.0123456789abcdef';
check('captcha: challenge well-formed and fresh', df_captcha_challenge_ok($ch, $tc + 5), true);
check('captcha: challenge expired after 10 min', df_captcha_challenge_ok($ch, $tc + DF_CAPTCHA_TTL + 1), false);
check('captcha: malformed challenge', [df_captcha_challenge_ok('x.y', $tc), df_captcha_challenge_ok('', $tc), df_captcha_challenge_ok($ch . '0', $tc)], [false, false, false]);
$ans = df_captcha_answer($ch);
check('captcha: answer is 5 letters from the unambiguous alphabet', preg_match('/^[' . DF_CAPTCHA_ALPHABET . ']{5}$/', $ans) === 1 && strpbrk($ans, '0O1IL') === false, true);
check('captcha: answer is deterministic per challenge', df_captcha_answer($ch), $ans);
check('captcha: different challenges, different answers (this pair)', df_captcha_answer('1100000000.fedcba9876543210') !== $ans, true);
check('captcha: wrong answer rejected', df_captcha_check($ch, 'ZZZZZ' === $ans ? 'YYYYY' : 'ZZZZZ', $tc + 5), false);
check('captcha: right answer (lower case, spaces) accepted', df_captcha_check($ch, ' ' . strtolower(substr($ans, 0, 2)) . ' ' . substr($ans, 2), $tc + 5), true);
check('captcha: a solved challenge cannot be used again', df_captcha_check($ch, $ans, $tc + 6), false);
check('captcha: right answer to an expired challenge rejected', df_captcha_check('1100000000.1111111111111111', df_captcha_answer('1100000000.1111111111111111'), $tc + DF_CAPTCHA_TTL + 5), false);
$tok = df_captcha_token($tc);
$tid = df_captcha_token_id($tok, $tc + 10);
check('captcha token: ours and fresh -> its id', is_string($tid) && strlen($tid) === 16, true);
check('captcha token: carries no client data (expiry.id.hmac only)', preg_match('/^[0-9]+\.[0-9a-f]{16}\.[0-9a-f]{64}$/', $tok), 1);
check('captcha token: expired rejected', df_captcha_token_id($tok, $tc + DF_CAPTCHA_TOKEN_TTL + 1), null);
[$te, $ti, $tsig] = explode('.', $tok);
check('captcha token: tampered hmac rejected', df_captcha_token_id($te . '.' . $ti . '.' . str_repeat('0', 64), $tc + 10), null);
check('captcha token: changed id rejected', df_captcha_token_id($te . '.' . strrev($ti) . '.' . $tsig, $tc + 10), null);
check('captcha token: extended expiry rejected', df_captcha_token_id(((int)$te + 3600) . '.' . $ti . '.' . $tsig, $tc + 10), null);
check('captcha token: forged with another key rejected', df_captcha_token_id($te . '.' . $ti . '.' . hash_hmac('sha256', 'captok|' . $te . '.' . $ti, 'not-our-secret'), $tc + 10), null);
check('captcha token: garbage rejected', [df_captcha_token_id('', $tc), df_captcha_token_id('abc', $tc)], [null, null]);
// per-token budget: a replayed token is worth captcha_token_budget, not unlimited
$GLOBALS['DF_CFG']['captcha_token_budget'] = 2;
$_COOKIE['df_cap'] = df_captcha_token($tc);
$cs0 = df_daily_count('capspent');
check('captcha pass: 1st over-cap fetch on the token', df_captcha_pass('tstcap', 100, $tc + 10), true);
check('captcha pass: token budget left before the 2nd', df_captcha_token_left($tc + 10), true);
check('captcha pass: 2nd', df_captcha_pass('tstcap', 100, $tc + 10), true);
check('captcha pass: replay past the budget refused', df_captcha_pass('tstcap', 100, $tc + 10), false);
check('captcha pass: spent counted in capspent', df_daily_count('capspent'), $cs0 + 1);
check('captcha pass: no budget left', df_captcha_token_left($tc + 10), false);
check('captcha pass: budget is per token id (a new token passes)', ($_COOKIE['df_cap'] = df_captcha_token($tc)) !== '' && df_captcha_pass('tstcap', 100, $tc + 10), true);
$GLOBALS['DF_CFG']['captcha_enabled'] = false;
check('captcha pass: off -> no pass even with a token', df_captcha_pass('tstcap', 100, $tc + 10), false);
[$GLOBALS['DF_CFG']['captcha_enabled'], $GLOBALS['DF_CFG']['captcha_token_budget']] = $capCfg;
unset($_COOKIE['df_cap']);
check('captcha pass: no cookie -> no pass', df_captcha_pass('tstcap', 100, $tc + 10), false);
// site-wide ceiling on token-funded units (HK-47 review): tokens add at most
// (captcha_ceiling_mult - 1) x cap per bucket per hour, then nobody passes
$ceilSaved = $GLOBALS['DF_CFG']['captcha_ceiling_mult'] ?? null;
$GLOBALS['DF_CFG']['captcha_ceiling_mult'] = 2;
$tce = $tc + 7200;                                 // a fresh hour for these buckets
check('captcha ceiling: (mult-1) x cap', [df_captcha_ceiling(3), df_captcha_ceiling(0)], [3, 0]);
$cl0 = df_daily_count('capceiltestceiling');
$ceilPass = [];
for ($i = 0; $i < 4; $i++) { $_COOKIE['df_cap'] = df_captcha_token($tce); $ceilPass[] = df_captcha_pass('ceiltest', 3, $tce + 10); }
check('captcha ceiling: 3 token units pass with cap 3, the 4th (fresh token) is refused', $ceilPass, [true, true, true, false]);
check('captcha ceiling: refusal counted in cap<bucket>ceiling', df_daily_count('capceiltestceiling'), $cl0 + 1);
check('captcha ceiling: reached', df_captcha_ceiling_hit('ceiltest', 3, $tce + 10), true);
check('captcha ceiling: per bucket (another bucket still open)', df_captcha_ceiling_hit('ceilother', 3, $tce + 10), false);
check('captcha ceiling: next hour resets', df_captcha_ceiling_hit('ceiltest', 3, $tce + 3600 + 10), false);
$GLOBALS['DF_CFG']['captcha_ceiling_mult'] = 1;
$_COOKIE['df_cap'] = df_captcha_token($tce);
check('captcha ceiling: mult 1 = tokens add nothing', df_captcha_pass('ceilone', 3, $tce + 10), false);
unset($_COOKIE['df_cap']);
$GLOBALS['DF_CFG']['captcha_ceiling_mult'] = $ceilSaved;
check('example config: captcha_ceiling_mult default', df_cfg('captcha_ceiling_mult'), 2);
check('captcha return: same-site path kept', df_captcha_return('/read.php?url=http%3A%2F%2Fa.b%2F&year=1999'), '/read.php?url=http%3A%2F%2Fa.b%2F&year=1999');
check('captcha return: open-redirect shapes become /', [df_captcha_return('//evil.example/'), df_captcha_return('http://evil.example/'),
      df_captcha_return('/\\evil.example'), df_captcha_return("/a\r\nLocation: x"), df_captcha_return(''), df_captcha_return('/' . str_repeat('a', 2001))],
      ['/', '/', '/', '/', '/', '/']);
$cg = df_captcha_gif($ch);
$cgi = @imagecreatefromstring($cg);
check('captcha gif: a 200x60 GIF', [strncmp($cg, 'GIF8', 4), $cgi !== false ? [imagesx($cgi), imagesy($cgi)] : null], [0, [200, 60]]);
// Page runs (same eval pattern as above). $setup runs in the child first.
function page_cli(string $page, string $setup): string {
    $code = '$GLOBALS["argv"] = [];'
          . 'ini_set("display_errors", "stderr");'
          . 'require ' . var_export(__DIR__ . '/../public/lib.php', true) . ';'
          . '$GLOBALS["DF_CFG"]["cache_dir"] = ' . var_export($GLOBALS['tmpCache'], true) . ';'
          . '$_COOKIE = ["df_pob" => df_pob_token()];'
          . $setup
          . 'register_shutdown_function(function () { echo "\nCODE=" . http_response_code(); });'
          . '$src = (string)file_get_contents(' . var_export(__DIR__ . '/../public/' . $page, true) . ');'
          . '$src = preg_replace("/^require __DIR__ \\\\. \'\\\\/lib\\\\.php\';$/m", "", $src, 1);'
          . 'eval("?>" . $src);';
    return (string)shell_exec(escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg($code) . ' 2>/dev/null');
}
// a high ceiling multiplier so these runs exercise the per-token budget, not the ceiling
$readSpent = '$GLOBALS["DF_CFG"]["read_hourly_cap"] = 1; $GLOBALS["DF_CFG"]["captcha_ceiling_mult"] = 1000; df_hourly_inc_capped("read", 1);';
$rq = 'https://example.invalid/captcha-' . getmypid();
// over the reader cap, no token: the captcha (503), counted
$cs1 = df_daily_count('capshown');
$pc = page_cli('read.php', $readSpent . '$_GET = ["url" => ' . var_export($rq, true) . ']; $_SERVER["REQUEST_URI"] = "/read.php?url=x";');
check('captcha page: 503', strpos($pc, "\nCODE=503") !== false, true);
check('captcha page: form with picture, answer field and return path', [strpos($pc, 'action="/captcha.php"') !== false,
      preg_match('#<img src="/captcha\.php\?c=[0-9]+\.[0-9a-f]{16}"#', $pc), strpos($pc, 'name="a"') !== false,
      strpos($pc, 'name="r" value="/read.php?url=x"') !== false], [true, 1, true, true]);
check('captcha page: alt text for text browsers', strpos($pc, 'try again after the top of the hour.]') !== false, true);
check('captcha page: capshown counted', df_daily_count('capshown'), $cs1 + 1);
check('captcha page: no fetch attempted', strpos($pc, 'Could not load') === false, true);
// over the reader cap WITH a valid token: proceeds to the fetch (example.invalid
// never resolves, so "Could not load" proves it got past the cap)
$vt = df_captcha_token();
$vid = (string)df_captcha_token_id($vt);
$pt = page_cli('read.php', $readSpent . '$_COOKIE["df_cap"] = ' . var_export($vt, true) . '; $_GET = ["url" => ' . var_export($rq, true) . '];');
check('captcha token: over the cap, the request proceeds', [strpos($pt, "\nCODE=503") === false, strpos($pt, 'Could not load') !== false], [true, true]);
check('captcha token: one unit of its own budget used', df_hourly_count('captok' . $vid), 1);
// the same token replayed past its budget: the captcha again
$cs2 = df_daily_count('capspent'); $cs3 = df_daily_count('capshown');
$pr = page_cli('read.php', $readSpent . '$GLOBALS["DF_CFG"]["captcha_token_budget"] = 1; $_COOKIE["df_cap"] = ' . var_export($vt, true) . '; $_GET = ["url" => ' . var_export($rq, true) . '];');
check('captcha token replayed past its budget: captcha again', [strpos($pr, "\nCODE=503") !== false, strpos($pr, 'action="/captcha.php"') !== false], [true, true]);
check('captcha token replayed past its budget: capspent + capshown', [df_daily_count('capspent'), df_daily_count('capshown')], [$cs2 + 1, $cs3 + 1]);
// the reader's token ceiling reached: a valid, unspent token gets the PLAIN
// busy page -- no captcha, no fetch -- and the ceiling refusal is counted
$cr0 = df_daily_count('capreadceiling');
$ceilSpent = '$GLOBALS["DF_CFG"]["read_hourly_cap"] = 1; $GLOBALS["DF_CFG"]["captcha_ceiling_mult"] = 2;'
           . 'df_hourly_inc_capped("read", 1); df_hourly_inc_capped("capceilread", 1);';
$pce = page_cli('read.php', $ceilSpent . '$_COOKIE["df_cap"] = ' . var_export(df_captcha_token(), true) . '; $_GET = ["url" => ' . var_export($rq, true) . '];');
check('captcha ceiling reached: 503 plain busy page, no captcha, no fetch',
      [strpos($pce, "\nCODE=503") !== false, strpos($pce, 'The reader is busy') !== false, strpos($pce, 'action="/captcha.php"') === false, strpos($pce, 'Could not load') === false],
      [true, true, true, true]);
check('captcha ceiling reached: capreadceiling counted', df_daily_count('capreadceiling'), $cr0 + 1);
// an expired / forged token over the cap: captcha
$pf = page_cli('read.php', $readSpent . '$_COOKIE["df_cap"] = ' . var_export($te . '.' . $ti . '.' . $tsig, true) . '; $_GET = ["url" => ' . var_export($rq, true) . '];');
check('captcha: expired token over the cap -> captcha', strpos($pf, 'action="/captcha.php"') !== false, true);
$pg = page_cli('read.php', $readSpent . '$_COOKIE["df_cap"] = ' . var_export(substr($vt, 0, -1) . (substr($vt, -1) === 'a' ? 'b' : 'a'), true) . '; $_GET = ["url" => ' . var_export($rq, true) . '];');
check('captcha: tampered token over the cap -> captcha', strpos($pg, 'action="/captcha.php"') !== false, true);
// search over its hourly cap, no token: captcha too
$ps = page_cli('index.php', '$GLOBALS["DF_CFG"]["search_hourly_cap"] = 1; df_hourly_inc_capped("search", 1); $_GET = ["q" => "captcha search ' . getmypid() . '"];');
check('captcha: search over cap -> captcha', [strpos($ps, "\nCODE=503") !== false, strpos($ps, 'action="/captcha.php"') !== false], [true, true]);
// map page with the tile budget spent: captcha; with a token: the page
$pm = page_cli('map.php', '$GLOBALS["DF_CFG"]["map_tile_hourly_cap"] = 1; df_hourly_inc_capped("maptile", 1); $_GET = [];');
check('captcha: map page with tiles spent -> captcha', strpos($pm, 'action="/captcha.php"') !== false, true);
$pmt = page_cli('map.php', '$GLOBALS["DF_CFG"]["map_tile_hourly_cap"] = 1; df_hourly_inc_capped("maptile", 1); $_COOKIE["df_cap"] = ' . var_export(df_captcha_token(), true) . '; $_GET = [];');
check('captcha: map page with tiles spent + token -> map page', strpos($pmt, 'action="/captcha.php"') === false && strpos($pmt, "\nCODE=503") === false, true);
// captcha.php: the picture, a right answer, a wrong one, a replay, a bad return path
$cc = df_captcha_new();
$pi = page_cli('captcha.php', '$_SERVER["REQUEST_METHOD"] = "GET"; $_GET = ["c" => ' . var_export($cc, true) . ']; ob_start(function ($b) { return base64_encode($b); });');
check('captcha.php GET: the GIF', strncmp((string)base64_decode(strtok($pi, "\n"), true), 'GIF8', 4), 0);
$pb = page_cli('captcha.php', '$_SERVER["REQUEST_METHOD"] = "GET"; $_GET = ["c" => "nope"];');
check('captcha.php GET: bad challenge 404', strpos($pb, "\nCODE=404") !== false, true);
$cv0 = df_daily_count('capsolved'); $cf0 = df_daily_count('capfailed');
$post = function (string $c, string $a, string $r) {
    return '$_SERVER["REQUEST_METHOD"] = "POST"; $_POST = ["c" => ' . var_export($c, true) . ', "a" => ' . var_export($a, true) . ', "r" => ' . var_export($r, true) . '];';
};
$pw = page_cli('captcha.php', $post($cc, 'ZZZZZ' === df_captcha_answer($cc) ? 'YYYYY' : 'ZZZZZ', '/read.php?url=x'));
check('captcha.php POST wrong: 403, new captcha, capfailed', [strpos($pw, "\nCODE=403") !== false, strpos($pw, 'did not match') !== false, df_daily_count('capfailed')], [true, true, $cf0 + 1]);
$pok = page_cli('captcha.php', $post($cc, df_captcha_answer($cc), '/read.php?url=x'));
check('captcha.php POST right: 302 back, link + meta refresh, capsolved', [strpos($pok, "\nCODE=302") !== false,
      strpos($pok, 'href="/read.php?url=x"') !== false, strpos($pok, 'http-equiv="refresh"') !== false, df_daily_count('capsolved')], [true, true, true, $cv0 + 1]);
$prp = page_cli('captcha.php', $post($cc, df_captcha_answer($cc), '/read.php?url=x'));
check('captcha.php POST replayed answer: rejected', [strpos($prp, "\nCODE=403") !== false, df_daily_count('capsolved')], [true, $cv0 + 1]);
$cc2 = df_captcha_new();
$pev = page_cli('captcha.php', $post($cc2, df_captcha_answer($cc2), '//evil.example/x'));
check('captcha.php: open-redirect return path goes to /', [strpos($pev, 'href="/"') !== false, strpos($pev, 'evil.example') === false], [true, true]);

// --- search fallback: Brave Search API (added 2026-11-12) --------------------
// The synthetic JSON below follows the shape in Brave's web-search docs;
// tests/fixtures/brave-telescope.json is a real response (captured on bespin
// 2026-11-12: q=telescope, count=10, HTTP 200) checked further down.
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
// the real captured response: 10 web results, <strong> markup in descriptions,
// extra top-level blocks (discussions, infobox, mixed, videos) ignored
$braveReal = (string)file_get_contents(__DIR__ . '/fixtures/brave-telescope.json');
$brr = df_brave_parse($braveReal);
check('brave real: 10 results', count($brr ?? []), 10);
check('brave real: first result', [$brr[0]['title'] ?? '', $brr[0]['url'] ?? ''], ['Telescopes – Celestron', 'https://www.celestron.com/collections/telescopes']);
check('brave real: no markup left in titles or snippets', count(array_filter($brr ?? [], function ($r) { return $r['title'] !== strip_tags($r['title']) || $r['snippet'] !== strip_tags($r['snippet']) || strpos($r['snippet'], '<') !== false; })), 0);
check('brave real: every url http(s), every snippet non-empty', count(array_filter($brr ?? [], function ($r) { return !preg_match('#^https?://#', $r['url']) || $r['snippet'] === ''; })), 0);
check('brave real: raw descriptions did carry <strong> (the strip matters)', strpos($braveReal, '<strong>') !== false || strpos($braveReal, '<strong>') !== false, true);
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
// (these runs pin search_primary to 'ddg': Brave as the fallback)
$braveStub = '$GLOBALS["DF_CFG"]["brave_api_key"] = "test-key-not-real"; $GLOBALS["DF_CFG"]["search_primary"] = "ddg";'
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
check('about: no Brave line without a key', strpos(about_html([]), 'Brave Search API') !== false, false);
check('about: Brave fallback line when configured with DDG primary', strpos(about_html(['brave_api_key' => 'k', 'search_primary' => 'ddg']), 'searches go to the Brave Search API') !== false, true);
check('about: Brave primary, DDG fallback', strpos(about_html(['brave_api_key' => 'k']), 'Search is powered by the Brave Search API') !== false
      && strpos(about_html(['brave_api_key' => 'k']), 'with DuckDuckGo as a fallback') !== false, true);
check('about: Brave only (DDG off)', strpos(about_html(['brave_api_key' => 'k', 'ddg_enabled' => false]), 'DuckDuckGo as a fallback') !== false, false);
check('about: no key = DDG as before', strpos(about_html(['search_primary' => 'brave']), 'Search is powered by DuckDuckGo') !== false, true);
// --- search_primary = brave (default) / ddg_enabled (added 2026-11-12) ---------
check('example config: search_primary / ddg_enabled defaults', [df_cfg('search_primary'), df_cfg('ddg_enabled')], ['brave', true]);
check('primary: no Brave key -> ddg', df_search_primary(), 'ddg');
$GLOBALS['DF_CFG']['brave_api_key'] = 'k';
check('primary: Brave key -> brave', df_search_primary(), 'brave');
$GLOBALS['DF_CFG']['search_primary'] = 'ddg';
check('primary: configured ddg', df_search_primary(), 'ddg');
$GLOBALS['DF_CFG']['search_primary'] = 'brave';
$GLOBALS['DF_CFG']['ddg_enabled'] = false;
check('ddg_enabled false honoured while Brave is usable', df_ddg_enabled(), false);
unset($GLOBALS['DF_CFG']['brave_api_key']);
check('ddg_enabled false ignored without Brave (search keeps a backend)', df_ddg_enabled(), true);
$GLOBALS['DF_CFG']['ddg_enabled'] = true;
$bp = '$GLOBALS["DF_CFG"]["brave_api_key"] = "test-key-not-real";'
    . '$GLOBALS["DF_TEST_BRAVE"] = function ($u, $h) { echo "BRAVE-CALLED"; return ["status" => 200, "ctype" => "application/json", "url" => $u, "body" => '
    . var_export($braveJson, true) . ']; };';
// (no echo in this stub: output before the page sets its status would hide a 503;
// Brave calls show in the daily 'brave' counter instead)
$bfail = '$GLOBALS["DF_CFG"]["brave_api_key"] = "test-key-not-real";'
       . '$GLOBALS["DF_TEST_BRAVE"] = function ($u, $h) { return ["status" => 500, "ctype" => "text/html", "url" => $u, "body" => ""]; };';
// Brave primary, DDG fine: Brave answers first; DDG never asked even with its html answer cached
reset_ddg_state(); df_ddg_backoff_clear('brave');
$qa = $sq(); $bva = df_daily_count('brave');
$pa = search_cli($qa, $bp . seed_ddg($lurl($qa), 200, 'ddg-lite-results.html'));
check('brave primary: Brave called, results rendered as Brave', [strpos($pa, 'BRAVE-CALLED') !== false, strpos($pa, 'Classic Mac Museum') !== false, strpos($pa, 'Results from Brave Search.') !== false], [true, true, true]);
check('brave primary: DDG not used (lite answer cached but not served, no ddglite)', strpos($pa, '<ol start="1">') !== false && df_daily_count('brave') === $bva + 1, true);
// Brave primary fails: DDG fallback (html backing off -> lite, from the cache)
df_ddg_backoff_hit('html');
$qb = $sq(); $ltb = df_daily_count('ddglite'); $bvb = df_daily_count('brave');
$pb = search_cli($qb, $bfail . seed_ddg($lurl($qb), 200, 'ddg-lite-results.html'));
check('brave primary failed: Brave tried, then DDG lite serves', [df_daily_count('brave'), df_daily_count('ddglite'), strpos($pb, 'from Brave Search') === false], [$bvb + 1, $ltb + 1, true]);
// Brave's daily cap spent: Brave not called, DDG serves
$qc = $sq();
$pc2 = search_cli($qc, $bp . '$GLOBALS["DF_CFG"]["brave_daily_cap"] = 1; df_daily_inc_capped("brave", 1);' . seed_ddg($lurl($qc), 200, 'ddg-lite-results.html'));
check('brave cap spent (primary): not called, DDG serves', [strpos($pc2, 'BRAVE-CALLED') === false, strpos($pc2, '<ol start="1">') !== false], [true, true]);
// DDG switched off and Brave fails: 503 unavailable, no DDG even with lite cached, searchnone counted
reset_ddg_state();
$qd = $sq(); $sn0 = df_daily_count('searchnone'); $lt4 = df_daily_count('ddglite'); $bvd = df_daily_count('brave');
$pd = search_cli($qd, $bfail . '$GLOBALS["DF_CFG"]["ddg_enabled"] = false;' . seed_ddg($lurl($qd), 200, 'ddg-lite-results.html'));
check('ddg off, Brave failed: 503 unavailable', [strpos($pd, "\nCODE=503") !== false, strpos($pd, 'Search is temporarily unavailable') !== false], [true, true]);
check('ddg off: Brave tried, DDG not used, searchnone counted', [df_daily_count('brave'), df_daily_count('ddglite'), df_daily_count('searchnone')], [$bvd + 1, $lt4, $sn0 + 1]);
// DDG off, shared hourly cap spent: busy page (no Brave call)
$pe = search_cli($sq(), $bp . '$GLOBALS["DF_CFG"]["ddg_enabled"] = false; $GLOBALS["DF_CFG"]["captcha_enabled"] = false; $GLOBALS["DF_CFG"]["search_hourly_cap"] = 1; df_hourly_inc_capped("search", 1);');
check('ddg off, hourly cap spent: busy page, Brave not called', [strpos($pe, 'Search is busy') !== false, strpos($pe, 'BRAVE-CALLED') === false], [true, true]);
reset_ddg_state(); df_ddg_backoff_clear('brave');
check('engine name: DDG without a Brave key', df_search_engine_name(), 'DuckDuckGo');
check('ddg off, hourly cap: busy page names Brave Search', strpos($pe, 'new searches to Brave Search each hour') !== false, true);
check('ddg off, Brave failed: unavailable page names Brave Search', strpos($pd, 'Brave Search is not answering') !== false, true);
check('about: daily budget line names the primary engine', strpos(about_html(['brave_api_key' => 'k']), 'cache misses sent to Brave Search') !== false, true);
// footer: 'search powered by' follows the primary engine (name and link)
check('footer: DDG without a Brave key', strpos(page_foot(), 'search powered by <a href="https://duckduckgo.com/">DuckDuckGo</a>') !== false, true);
$GLOBALS['DF_CFG']['brave_api_key'] = 'k';
check('footer: Brave primary', [strpos(page_foot(), 'search powered by <a href="https://brave.com/search/">Brave Search</a>') !== false, strpos(page_foot(), 'DuckDuckGo') === false], [true, true]);
$GLOBALS['DF_CFG']['search_primary'] = 'ddg';
check('footer: DDG primary with a Brave key', strpos(page_foot(), 'search powered by <a href="https://duckduckgo.com/">DuckDuckGo</a>') !== false, true);
$GLOBALS['DF_CFG']['search_primary'] = 'brave';
unset($GLOBALS['DF_CFG']['brave_api_key']);
reset_ddg_state(); df_ddg_backoff_clear('brave');

// --- reader render fallback (added 2026-11-12) -------------------------------
check('example config: render off by default', [df_cfg('render_url'), df_render_enabled()], ['', false]);
check('example config: render defaults', [df_cfg('render_hourly_cap'), df_cfg('render_min_text'), df_cfg('render_ua_mode')], [60, 400, 'chrome']);
check('challenge re: captcha page is a challenge', preg_match(DF_CHALLENGE_RE, 'Checking your browser before accessing') === 1, true);
check('challenge re: a plain "enable JavaScript" notice is NOT a challenge', preg_match(DF_CHALLENGE_RE, 'You need to enable JavaScript to run this app.') === 1, false);
$rnTag = getmypid() . '-' . mt_rand();
$rnShell = '<!doctype html><html><head><title>App</title></head><body><div id="root"></div>'
         . '<noscript>You need to enable JavaScript to run this app.</noscript></body></html>';
$rnFull = '<html><head><title>Rendered Story</title></head><body><article><h1>Rendered Story</h1><p>'
        . str_repeat('This sentence was put on the page by JavaScript and only the renderer sees it. ', 20)
        . '</p></article><noscript>You need to enable JavaScript to run this app.</noscript></body></html>';
$rnLog = $GLOBALS['tmpCache'] . '/render-seam-' . $rnTag;
// seed a cached raw fetch for $u (read.php's own cache key) and wire the render seam
function render_setup(string $u, string $body, array $resp, string $log, string $extra = ''): string {
    return 'df_cache_put(' . var_export('raw:' . $u, true) . ', serialize(["status" => 200, "ctype" => "text/html", "url" => '
         . var_export($u, true) . ', "body" => ' . var_export($body, true) . ']));'
         . '$GLOBALS["DF_CFG"]["render_url"] = "https://relay.example.invalid/"; $GLOBALS["DF_CFG"]["relay_secret"] = "rs-test";'
         . '$GLOBALS["DF_TEST_RENDER"] = function ($e, $p, $h) { file_put_contents(' . var_export($log, true) . ', $e . "\n" . $p . "\n" . implode("|", $h)); return '
         . var_export($resp, true) . '; };'
         . $extra;
}
$rnOk = ['status' => 200, 'body' => json_encode(['status' => 'ok', 'final_url' => 'https://app.example/story', 'html' => $rnFull, 'truncated' => false, 'ms' => 900])];
// (1) JS shell page: rendered, extracted, used; counted; the request carried url, ua and secret
$u1 = 'https://app.example/story-' . $rnTag;
$c0 = [df_daily_count('render'), df_daily_count('renderok')];
@unlink($rnLog);
$o1 = page_cli('read.php', render_setup($u1, $rnShell, $rnOk, $rnLog) . '$_GET = ["url" => ' . var_export($u1, true) . '];');
check('render: JS-built page rendered and shown', [strpos($o1, 'only the renderer sees it') !== false, strpos($o1, 'built by JavaScript') !== false], [true, true]);
check('render: not shown as blocked (noscript text in the rendered DOM ignored)', strpos($o1, 'Site is blocking automated access') === false, true);
check('render: counted render + renderok', [df_daily_count('render'), df_daily_count('renderok')], [$c0[0] + 1, $c0[1] + 1]);
$sl = (string)@file_get_contents($rnLog);
check('render: POST to <render_url>/render', strpos($sl, "https://relay.example.invalid/render\n") === 0, true);
check('render: payload is the url + ua chrome', strpos($sl, json_encode(['url' => $u1, 'ua' => 'chrome'])) !== false, true);
check('render: shared secret header', strpos($sl, 'X-Relay-Secret: rs-test') !== false, true);
// (2) cached: a second read of the same URL does not call the service
@unlink($rnLog);
$o2 = page_cli('read.php', render_setup($u1, $rnShell, $rnOk, $rnLog) . '$_GET = ["url" => ' . var_export($u1, true) . '];');
check('render: cached result reused, service not called', [strpos($o2, 'only the renderer sees it') !== false, is_file($rnLog)], [true, false]);
// (3) render off: the old behaviour (shown as blocked, no call)
$u3 = 'https://app.example/off-' . $rnTag;
@unlink($rnLog);
$o3 = page_cli('read.php', render_setup($u3, $rnShell, $rnOk, $rnLog, '$GLOBALS["DF_CFG"]["render_url"] = "";') . '$_GET = ["url" => ' . var_export($u3, true) . '];');
// (the extractor drops <noscript>, so this shell was never shown as "blocked": same as before)
check('render off: no call, no render note', [is_file($rnLog), strpos($o3, 'built by JavaScript') === false], [false, true]);
// (4) a real challenge page is never sent to the renderer
$u4 = 'https://app.example/chal-' . $rnTag;
@unlink($rnLog);
$o4 = page_cli('read.php', render_setup($u4, '<html><head><title>Just a moment...</title></head><body>Checking your browser before accessing.</body></html>', $rnOk, $rnLog) . '$_GET = ["url" => ' . var_export($u4, true) . '];');
check('render: challenge page not rendered, shown as blocked', [is_file($rnLog), strpos($o4, 'Site is blocking automated access') !== false], [false, true]);
// (5) a page with enough text is not rendered
$u5 = 'https://app.example/long-' . $rnTag;
@unlink($rnLog);
$o5 = page_cli('read.php', render_setup($u5, '<html><head><title>Long</title></head><body><article><p>' . str_repeat('Plenty of server-side text here. ', 40) . '</p></article></body></html>', $rnOk, $rnLog) . '$_GET = ["url" => ' . var_export($u5, true) . '];');
check('render: long page not rendered', [is_file($rnLog), strpos($o5, 'Plenty of server-side text') !== false], [false, true]);
// (5b) render hardening (2026-11-12): an error screen from the renderer is a
// failure; a failure or backoff shows a visible note instead of silence
$wowErr = '<html><head><title>Wowhead</title></head><body><h1>Wowhead - Static CDN Error</h1><p>'
        . 'Your browser can&#39;t reach the server where we host our styles, scripts, and images. '
        . str_repeat('Please check your connection and try again later. ', 15) . '</p></body></html>';
check('render error re: wowhead CDN screen', df_render_is_error($wowErr), true);
check('render error re: a normal rendered page is not an error', df_render_is_error($rnFull), false);
check('render error re: a long article that merely quotes the phrase is not an error',
      df_render_is_error('<p>' . str_repeat('A long real article about web outages. ', 150) . 'Static CDN Error</p>'), false);
$u5b = 'https://app.example/cdnerr-' . $rnTag;
$rf0 = df_daily_count('renderfail');
$o5b = page_cli('read.php', render_setup($u5b, $rnShell, ['status' => 200, 'body' => json_encode(['status' => 'ok', 'final_url' => $u5b, 'html' => $wowErr, 'truncated' => false, 'ms' => 1400])], $rnLog)
    . '$_GET = ["url" => ' . var_export($u5b, true) . '];');
check('render error screen: not shown as the page; failure note shown',
      [strpos($o5b, 'Static CDN Error') === false, strpos($o5b, 'couldn&#39;t render it right now') !== false], [true, true]);
check('render error screen: counted as renderfail, not cached', [df_daily_count('renderfail'), df_cache_get('render:' . $u5b, 1800)], [$rf0 + 1, null]);
$u5c = 'https://app.example/svcfail-' . $rnTag;
$o5c = page_cli('read.php', render_setup($u5c, $rnShell, ['status' => 502, 'body' => '{"status":"unstable"}'], $rnLog)
    . '$_GET = ["url" => ' . var_export($u5c, true) . '];');
check('render 502: failure note shown', strpos($o5c, 'couldn&#39;t render it right now') !== false, true);
$u5d = 'https://app.example/backoff-' . $rnTag;
@unlink($rnLog);
$o5d = page_cli('read.php', render_setup($u5d, $rnShell, $rnOk, $rnLog, 'df_ddg_backoff_hit("render");')
    . '$_GET = ["url" => ' . var_export($u5d, true) . '];');
check('render backing off: not called, failure note shown', [is_file($rnLog), strpos($o5d, 'couldn&#39;t render it right now') !== false], [false, true]);
df_ddg_backoff_clear('render');
// (6) render returns less text than the original: original kept, not counted as used
$u6 = 'https://app.example/short-' . $rnTag;
$k6 = df_daily_count('renderok');
$o6 = page_cli('read.php', render_setup($u6, '<html><head><title>Mid</title></head><body><article><p>' . str_repeat('Some text. ', 25) . '</p></article></body></html>',
      ['status' => 200, 'body' => json_encode(['status' => 'ok', 'final_url' => $u6, 'html' => '<html><body><p>tiny</p></body></html>'])], $rnLog) . '$_GET = ["url" => ' . var_export($u6, true) . '];');
check('render: shorter render loses, original kept', [strpos($o6, 'Some text.') !== false, df_daily_count('renderok')], [true, $k6]);
// (7) service busy: renderfail, render endpoint backs off, next read does not call
$u7 = 'https://app.example/busy-' . $rnTag;
df_ddg_backoff_clear('render');
$f7 = df_daily_count('renderfail');
page_cli('read.php', render_setup($u7, $rnShell, ['status' => 503, 'body' => '{"status":"busy"}'], $rnLog) . '$_GET = ["url" => ' . var_export($u7, true) . '];');
check('render busy: renderfail counted, render backs off', [df_daily_count('renderfail'), df_ddg_backoff_state('render')['level']], [$f7 + 1, 1]);
@unlink($rnLog);
page_cli('read.php', render_setup($u7 . 'b', $rnShell, $rnOk, $rnLog) . '$_GET = ["url" => ' . var_export($u7 . 'b', true) . '];');
check('render backing off: service not called', is_file($rnLog), false);
df_ddg_backoff_clear('render');
// (8) a 400 from the service (refused URL) is a failure but no backoff
$u8 = 'https://app.example/refused-' . $rnTag;
page_cli('read.php', render_setup($u8, $rnShell, ['status' => 400, 'body' => '{"status":"blocked","reason":"address"}'], $rnLog) . '$_GET = ["url" => ' . var_export($u8, true) . '];');
check('render refused (400): no backoff', is_file(df_ddg_backoff_file('render')), false);
// (9) hourly cap spent: note shown, rendercapped counted, service not called
$u9 = 'https://app.example/capped-' . $rnTag;
$rc9 = df_daily_count('rendercapped');
@unlink($rnLog);
$o9 = page_cli('read.php', render_setup($u9, $rnShell, $rnOk, $rnLog, '$GLOBALS["DF_CFG"]["render_hourly_cap"] = 1; df_hourly_inc_capped("render", 1);') . '$_GET = ["url" => ' . var_export($u9, true) . '];');
check('render capped: not called, counted', [is_file($rnLog), df_daily_count('rendercapped')], [false, $rc9 + 1]);
check('render capped: page says the renderer is done for the hour', strpos($o9, 'has done all it can for this hour') !== false, true);
// (10) honest UA mode is passed through
$u10 = 'https://app.example/ua-' . $rnTag;
@unlink($rnLog);
page_cli('read.php', render_setup($u10, $rnShell, $rnOk, $rnLog, '$GLOBALS["DF_CFG"]["render_ua_mode"] = "honest";') . '$_GET = ["url" => ' . var_export($u10, true) . '];');
check('render: honest UA mode sent', strpos((string)@file_get_contents($rnLog), '"ua":"honest"') !== false, true);
// (11) Wayback reads are never rendered
$u11 = 'https://app.example/wb-' . $rnTag;
@unlink($rnLog);
page_cli('read.php', render_setup($u11, $rnShell, $rnOk, $rnLog,
    'df_cache_put(' . var_export('wb:20010601000000:' . $u11, true) . ', serialize(["status" => 200, "ctype" => "text/html", "body" => ' . var_export($rnShell, true) . ']));')
    . '$_GET = ["url" => ' . var_export($u11, true) . ', "year" => "2001"];');
check('render: Wayback read not rendered', is_file($rnLog), false);
@unlink($rnLog);
check('about: render line only when the renderer is configured',
      [strpos(about_html([]), 'Pages that need JavaScript may be rendered') !== false,
       strpos(about_html(['render_url' => 'https://relay.example/', 'relay_secret' => 'x']),
              'Pages that need JavaScript may be rendered by DuckFind&#39;s own server-side browser. The page address passes through Cloudflare on the way.') !== false],
      [false, true]);

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
$ak = fn(string $u) => 'ascii' . DF_ASCII_VERSION . ':' . DF_ASCII_COLS . ':l::' . $u;
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

// --- ascii improvements (2026-11-12) -------------------------------------------
// (a) auto-levels gate 48 -> 16: a low-contrast photo (tones 112..150 here, a
// left-right ramp with a dark band) gets stretched instead of collapsing to
// one or two characters
$lc = imagecreatetruecolor(120, 60);
for ($x = 0; $x < 120; $x++) { $v = 112 + (int)round(38 * $x / 119); imageline($lc, $x, 0, $x, 59, imagecolorallocate($lc, $v, $v, $v)); }
$lcArt = html_entity_decode(df_ascii_art($lc, 40));
check('ascii levels: low-contrast image uses many characters', count(array_unique(str_split(str_replace("\n", '', $lcArt)))) >= 6, true);
check('ascii levels: gate constant', DF_ASCII_LEVELS_GATE, 16);
// (b) line art: a 1px box outline on white keeps its edges and a blank inside
$box = imagecreatetruecolor(300, 150);
imagefill($box, 0, 0, imagecolorallocate($box, 255, 255, 255));
imagerectangle($box, 20, 20, 279, 129, imagecolorallocate($box, 0, 0, 0));
$bxL = explode("\n", html_entity_decode(df_ascii_art($box, 40)));
$bxAll = implode('', $bxL);
check('ascii line art: vertical edges drawn with |', substr_count($bxAll, '|') >= 4, true);
check('ascii line art: horizontal edges drawn', preg_match('/[-_]{10,}/', $bxAll) === 1, true);
$mid = $bxL[(int)(count($bxL) / 2)] ?? '';
check('ascii line art: interior of the box is blank', trim(substr($mid, 6, 26)) === '', true);
// a grey (sepia-scan-like) paper with dark strokes: the paper goes blank
$sep = imagecreatetruecolor(300, 150);
imagefill($sep, 0, 0, imagecolorallocate($sep, 200, 190, 170));
imagesetthickness($sep, 2);
imageline($sep, 30, 30, 270, 120, imagecolorallocate($sep, 40, 30, 20));
$sepL = explode("\n", html_entity_decode(df_ascii_art($sep, 40)));
$sepAll = implode('', $sepL);
// lines are right-trimmed, so count inked characters against all cells
check('ascii paper whitening: tinted paper comes out blank', strlen(str_replace(' ', '', $sepAll)) < count($sepL) * 40 * 0.2, true);
check('ascii paper whitening: the stroke survives', trim($sepAll) !== '', true);
// photos (no dominant paper tone) keep using the ramp, never shape glyphs
check('ascii photo gradient has no shape glyphs', preg_match('#[|/\\\\_"\']#', $lcArt), 0);
// custom ramps never get shape glyphs either
check('ascii custom ramp on line art stays within the ramp', preg_match('/^[ ab\n]*$/', html_entity_decode(df_ascii_art($box, 40, false, ' ab'))), 1);
// (c) images too small or too flat for art fall back to alt text (inline path)
check('ascii worth: 32px icon no', df_ascii_worth_drawing(32, 32), false);
check('ascii worth: 88x31 button no', df_ascii_worth_drawing(88, 31), false);
check('ascii worth: 728x90 banner no (2 rows)', df_ascii_worth_drawing(728, 90), false);
check('ascii worth: 64x64 yes', df_ascii_worth_drawing(64, 64), true);
check('ascii worth: 500x300 photo yes', df_ascii_worth_drawing(500, 300), true);
check('ascii cache key carries a version', DF_ASCII_VERSION >= 2, true);
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

function rd_wrap_pre_cli(string $s): string {
    return page_fn_cli('read.php', 'echo rd_wrap_pre(' . var_export($s, true) . ', 76);');
}
// --- reader quality, Tier-1 items 1-6 (added 2026-11-12) --------------------
// extract_readable() run on small fixtures in a child (read.php's own code).
function rq_extract(string $html, string $base = 'https://ex.com/page'): array {
    $out = page_fn_cli('read.php', '$r = extract_readable(' . var_export($html, true) . ', ' . var_export($base, true) . ');'
        . ' echo json_encode([$r[0], $r[1]]);');
    $j = json_decode($out, true);
    return is_array($j) ? $j : ['', $out];
}
$rqText = fn(string $h) => trim(preg_replace('/\s+/', ' ', html_entity_decode(strip_tags($h), ENT_QUOTES, 'UTF-8')));
$rqPara = str_repeat('This is a sentence of real post text that a reader wants to see. ', 4);

// (1a) a thread where every post is an <article>: all posts, not just the first
$thread = '<html><head><title>Thread</title></head><body><div class="posts">';
for ($i = 1; $i <= 4; $i++) $thread .= '<article class="message"><div class="bbWrapper">Post number ' . $i . '. ' . $rqPara . '</div></article>';
$thread .= '</div></body></html>';
[, $c1] = rq_extract($thread);
check('reader thread: all four posts kept', [strpos($c1, 'Post number 1.') !== false, strpos($c1, 'Post number 4.') !== false], [true, true]);
// (1b) a comment-heavy page keeps its comments; a page with a small comment block still drops it
$hnLike = '<html><head><title>Discussion</title></head><body><p>' . str_repeat('Short intro. ', 5) . '</p>';
for ($i = 1; $i <= 5; $i++) $hnLike .= '<div class="comment">Comment ' . $i . ': ' . $rqPara . '</div>';
$hnLike .= '</body></html>';
[, $c1b] = rq_extract($hnLike);
check('reader comments: comment-heavy page keeps its comments', [strpos($c1b, 'Comment 1:') !== false, strpos($c1b, 'Comment 5:') !== false], [true, true]);
$artCmt = '<html><head><title>Article</title></head><body><article><p>' . str_repeat($rqPara, 6) . '</p></article>'
        . '<div class="comments"><div class="comment">Nice post!</div></div></body></html>';
[, $c1c] = rq_extract($artCmt);
check('reader comments: a small comment block on an article is still dropped', strpos($c1c, 'Nice post!'), false);

// (2) in-page links: local jump with a named anchor; a link to a stripped target is plain text
$fn = '<html><head><title>Notes</title></head><body><article><p>' . $rqPara . ' See note<a href="#fn1">1</a> and <a href="#gone">elsewhere</a>.</p>'
    . '<p>' . $rqPara . '</p><ol><li id="fn1">The footnote text.</li></ol></article></body></html>';
[, $c2] = rq_extract($fn);
check('reader anchors: local link kept as #fn1', strpos($c2, '<a href="#fn1">1</a>') !== false, true);
check('reader anchors: target gets <a name>', strpos($c2, '<li><a name="fn1"></a>The footnote text.') !== false, true);
check('reader anchors: link to a missing target is plain text', [strpos($c2, 'href="#gone"') === false, strpos($c2, 'elsewhere') !== false], [true, true]);
check('reader anchors: no proxied reload for #fragments', strpos($c2, '%23fn1'), false);
check('reader anchors: no <a name> for unlinked ids', strpos($c2, 'name="gone"'), false);

// (3) several h1s: title from <title>/og, the title's own h1 dropped, the rest demoted to h2
$mh = '<html><head><title>SELECT</title></head><body><main><h1>1. Overview</h1><p>' . $rqPara . '</p><h1>2. Details</h1><p>' . $rqPara . '</p></main></body></html>';
[$t3, $c3] = rq_extract($mh);
check('reader h1s: title is <title>, not section 1', $t3, 'SELECT');
check('reader h1s: section h1s kept as h2', [strpos($c3, '<h2>1. Overview</h2>') !== false, strpos($c3, '<h2>2. Details</h2>') !== false], [true, true]);
$mh2 = '<html><head><title>Big Essay - Site</title></head><body><main><h1>Big Essay</h1><p>' . $rqPara . '</p><h1>Part Two</h1><p>' . $rqPara . '</p></main></body></html>';
[$t3b, $c3b] = rq_extract($mh2);
check('reader h1s: the h1 the <title> echoes is the title and is not repeated', [$t3b, strpos($c3b, 'Big Essay')], ['Big Essay', false]);
check('reader h1s: the other h1 becomes h2', strpos($c3b, '<h2>Part Two</h2>') !== false, true);
$one = '<html><head><title>T - Site</title></head><body><main><h1>Only Heading</h1><p>' . $rqPara . '</p></main></body></html>';
[$t3c, $c3c] = rq_extract($one);
check('reader h1s: a single h1 behaves as before (title, stripped)', [$t3c, strpos($c3c, 'Only Heading')], ['Only Heading', false]);

// (4) div paragraphs, <br> inside cells, whitespace collapsed
$divs = '<html><head><title>Forum</title></head><body><main><div class="post">'
      . '<div class="text">First   paragraph   of the post. ' . $rqPara . '</div>'
      . '<div class="text">Second paragraph of the post. ' . $rqPara . '</div>'
      . '<table><tr><td><div>Cell line one</div><div>Cell line two</div></td></tr></table>'
      . '</div></main></body></html>';
[, $c4] = rq_extract($divs);
check('reader div2p: div paragraphs become <p>', substr_count($c4, '<p>First paragraph') + substr_count($c4, '<p>Second paragraph'), 2);
check('reader div2p: divs in a cell become line breaks', strpos($c4, 'Cell line one<br>') !== false, true);
check('reader ws: runs of spaces collapsed', strpos($c4, '   '), false);
$inl = '<html><head><title>Inl</title></head><body><main><p>' . $rqPara . ' <a href="/x"><div>card title</div></a></p></main></body></html>';
[, $c4b] = rq_extract($inl);
check('reader div2p: no <p> inside a link', strpos($c4b, '<a href="/read.php?url=https%3A%2F%2Fex.com%2Fx"><p>'), false);

// (5) code blocks: one line per highlighter line; long lines wrapped at 76
$code = '<html><head><title>Code</title></head><body><main><p>' . $rqPara . '</p><pre><code>'
      . '<div class="ec-line"><div class="code"><span>import x from "y";</span></div></div>'
      . '<div class="ec-line"><div class="code"><span>export default x;</span></div></div>'
      . '<span class="token-line">let a = 1;</span><span class="token-line">let b = 2;</span>'
      . '</code></pre><pre>' . str_repeat('A', 100) . '</pre></main></body></html>';
[, $c5] = rq_extract($code);
check('reader pre: highlighter lines keep their breaks', strpos($c5, "import x from &quot;y&quot;;\nexport default x;\nlet a = 1;\nlet b = 2;") !== false, true);
check('reader pre: no pad spaces inside pre', strpos($c5, "\n "), false);
check('reader pre: long line hard-wrapped at 76', strpos($c5, str_repeat('A', 76) . "\n" . str_repeat('A', 24)) !== false, true);
check('reader pre: wrap counts an entity as one column', rd_wrap_pre_cli(str_repeat('&lt;', 80)), str_repeat('&lt;', 76) . "\n" . str_repeat('&lt;', 4));
check('reader pre: <br> ends a line for the wrap', rd_wrap_pre_cli(str_repeat('B', 70) . '<br>' . str_repeat('C', 70)), str_repeat('B', 70) . '<br>' . str_repeat('C', 70));

// (6) figure + figcaption: caption once, small italic, alt not repeated
$fig = '<html><head><title>Fig</title></head><body><article><p>' . $rqPara . '</p><figure>'
     . '<img src="https://ex.com/a.jpg" alt="A long alt text for the photo"><figcaption>The real caption. Photo: Agency</figcaption>'
     . '</figure><p>' . $rqPara . '</p><img src="https://ex.com/b.jpg" alt="Loose image alt"></article></body></html>';
[, $c6] = rq_extract($fig);
check('reader figure: figcaption rendered as the small italic caption', strpos($c6, '<br><font size="1"><i>The real caption. Photo: Agency</i></font>') !== false, true);
check('reader figure: alt not repeated as a caption when a figcaption exists', strpos($c6, '<i>A long alt text for the photo</i>'), false);
check('reader figure: the figure is its own paragraph', preg_match('#<p><br><img [^>]*a\.jpg#', $c6), 1);
check('reader figure: an image outside a figure keeps its alt caption', strpos($c6, '<i>Loose image alt</i>') !== false, true);

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
    "if (df_cacheable_response(\$r) && !df_body_capped(\$r, \$maxlen)) df_cache_put(\$key, serialize(\$r));\n            return \$r;") !== false, true);

// --- dl.php / ftp.php: refuse a declared over-cap file before sending anything --
// (2026-11-10: a 150 MB file streamed 52 MB under a 200, then was cut off -- a
// corrupt download and no error page). Needs a live origin to exercise, so this
// only pins the guard in place; verified by hand against ftp.gnu.org.
foreach (['dl.php' => 'DL_MAX_BYTES', 'ftp.php' => 'FTP_MAX_BYTES'] as $pg => $capc) {
    check("$pg refuses declared over-cap size", strpos((string)file_get_contents(__DIR__ . '/../public/' . $pg),
        "curl_getinfo(\$ch, CURLINFO_CONTENT_LENGTH_DOWNLOAD) > $capc) return 0;") !== false, true);
}

// --- reader: signed result links (added 2026-11-12) --------------------------
$tkU = 'https://example.invalid/tok-' . getmypid() . '-' . mt_rand();
$tkNow = 2000000000;
$tk = df_readtok($tkU, $tkNow);
check('readtok: 24 hex', preg_match('/^[0-9a-f]{24}$/', $tk), 1);
check('readtok: same url+hour = same token', df_readtok($tkU, intdiv($tkNow, 3600) * 3600 + 3599), df_readtok($tkU, intdiv($tkNow, 3600) * 3600));
check('readtok: valid now', df_readtok_valid($tkU, $tk, $tkNow), true);
check('readtok: valid in the next hour (previous bucket)', df_readtok_valid($tkU, $tk, $tkNow + 3600), true);
check('readtok: expired two hours on', df_readtok_valid($tkU, $tk, $tkNow + 7200), false);
check('readtok: wrong URL', df_readtok_valid($tkU . 'x', $tk, $tkNow), false);
check('readtok: tampered', df_readtok_valid($tkU, substr($tk, 0, 23) . ($tk[23] === 'a' ? 'b' : 'a'), $tkNow), false);
check('readtok: junk/empty', [df_readtok_valid($tkU, '', $tkNow), df_readtok_valid($tkU, str_repeat('z', 24), $tkNow), df_readtok_valid($tkU, $tk . '00', $tkNow)], [false, false, false]);
check('readtok: binds nothing but url+hour (no client data in the MAC input)',
      strpos((string)file_get_contents(__DIR__ . '/../public/lib.php'), "'readtok|' . \$url . '|' . \$bucket") !== false, true);
check('readtok_qs', [df_readtok_qs($tkU), df_readtok_qs($tkU, true)], ['&t=' . df_readtok($tkU), '&amp;t=' . df_readtok($tkU)]);
// bypass: ceiling = mult x read_hourly_cap; invalid tokens have no side effects
$tkSaved = [$GLOBALS['DF_CFG']['read_hourly_cap'] ?? null, $GLOBALS['DF_CFG']['read_token_hourly_mult'] ?? null];
$GLOBALS['DF_CFG']['read_hourly_cap'] = 1; $GLOBALS['DF_CFG']['read_token_hourly_mult'] = 2;
$tb0 = df_daily_count('readtokbypass'); $tc0 = df_hourly_count('readtok', $tkNow);
check('bypass: tampered token, no unit spent', [df_read_token_bypass_ok($tkU, str_repeat('0', 24), $tkNow), df_hourly_count('readtok', $tkNow)], [false, $tc0]);
check('bypass: 1st and 2nd valid (ceiling 2x1)', [df_read_token_bypass_ok($tkU, $tk, $tkNow), df_read_token_bypass_ok($tkU, $tk, $tkNow)], [true, true]);
check('bypass: 3rd refused at the ceiling', df_read_token_bypass_ok($tkU, $tk, $tkNow), false);
check('bypass: counted in readtokbypass', df_daily_count('readtokbypass'), $tb0 + 2);
$GLOBALS['DF_CFG']['read_token_hourly_mult'] = 0;
check('bypass: mult 0 = off (fresh hour, valid token)', df_read_token_bypass_ok($tkU, df_readtok($tkU, $tkNow + 3600), $tkNow + 3600), false);
[$GLOBALS['DF_CFG']['read_hourly_cap'], $GLOBALS['DF_CFG']['read_token_hourly_mult']] = $tkSaved;
if ($tkSaved[0] === null) unset($GLOBALS['DF_CFG']['read_hourly_cap']);
if ($tkSaved[1] === null) unset($GLOBALS['DF_CFG']['read_token_hourly_mult']);
check('example config: read_token_hourly_mult default', df_cfg('read_token_hourly_mult'), 3);
check('read.php: per-IP rate limit still runs first (df_rate is a no-op in CLI, so pinned by source order)',
      (function () { $r = (string)file_get_contents(__DIR__ . '/../public/read.php');
                     $a = strpos($r, "df_rate('read')"); $b = strpos($r, 'df_read_token_bypass_ok(');
                     $g = strpos($r, 'df_require_browser_proof()');
                     return $a !== false && $b !== false && $g !== false && $a < $b && $g < $b; })(), true);
// page level: hourly read cap spent; a signed link proceeds, bad ones get the normal cap page
$tkSpent = '$GLOBALS["DF_CFG"]["read_hourly_cap"] = 1; $GLOBALS["DF_CFG"]["captcha_ceiling_mult"] = 1000; df_hourly_inc_capped("read", 1);';
$tkPage = 'https://example.invalid/tokpage-' . getmypid() . '-' . mt_rand();
$tb1 = df_daily_count('readtokbypass');
$p1 = page_cli('read.php', $tkSpent . '$_GET = ["url" => ' . var_export($tkPage, true) . ', "t" => df_readtok(' . var_export($tkPage, true) . ')];');
check('signed link: passes the spent cap (fetch attempted, no 503)', [strpos($p1, "\nCODE=503") === false, strpos($p1, 'Could not load') !== false], [true, true]);
check('signed link: counted', df_daily_count('readtokbypass'), $tb1 + 1);
$p2 = page_cli('read.php', $tkSpent . '$_GET = ["url" => ' . var_export($tkPage, true) . ', "t" => df_readtok(' . var_export($tkPage . '/other', true) . ')];');
check('token for another URL: normal cap (503), no fetch', [strpos($p2, "\nCODE=503") !== false, strpos($p2, 'Could not load') === false], [true, true]);
$p3 = page_cli('read.php', $tkSpent . '$_GET = ["url" => ' . var_export($tkPage, true) . ', "t" => "' . str_repeat('ab', 12) . '"];');
check('tampered token: normal cap (503), no error page of its own', [strpos($p3, "\nCODE=503") !== false, strpos($p3, 'Could not load') === false], [true, true]);
$p4 = page_cli('read.php', $tkSpent . '$_GET = ["url" => ' . var_export($tkPage, true) . ', "t" => df_readtok_at(' . var_export($tkPage, true) . ', intdiv(time(), 3600) - 2)];');
check('expired token: normal cap (503)', strpos($p4, "\nCODE=503") !== false, true);
$p5 = page_cli('read.php', $tkSpent . '$GLOBALS["DF_CFG"]["read_token_hourly_mult"] = 1; df_hourly_inc_capped("readtok", 1);'
    . '$_GET = ["url" => ' . var_export($tkPage, true) . ', "t" => df_readtok(' . var_export($tkPage, true) . ')];');
check('token ceiling reached: normal cap (503), no fetch', [strpos($p5, "\nCODE=503") !== false, strpos($p5, 'Could not load') === false], [true, true]);
// the render cap still applies to a signed read
$tkR = 'https://app.example/tok-render-' . getmypid() . '-' . mt_rand();
$tkLog = $GLOBALS['tmpCache'] . '/render-seam-tok-' . getmypid();
@unlink($tkLog);
$p6 = page_cli('read.php', render_setup($tkR, $rnShell, $rnOk, $tkLog,
        '$GLOBALS["DF_CFG"]["render_hourly_cap"] = 1; $GLOBALS["DF_CFG"]["captcha_enabled"] = false; df_hourly_inc_capped("render", 1);')
    . '$_GET = ["url" => ' . var_export($tkR, true) . ', "t" => df_readtok(' . var_export($tkR, true) . ')];');
check('signed link: render cap still applies (service not called, capped note)',
      [is_file($tkLog), strpos($p6, 'has done all it can for this hour') !== false], [false, true]);
// search results carry valid t for their own URL
reset_ddg_state(); df_ddg_backoff_clear('brave'); df_ddg_backoff_hit('html');
$tkQ = 'duckfind readtok test ' . getmypid();
$p7 = search_cli($tkQ, seed_ddg('https://lite.duckduckgo.com/lite/?q=' . urlencode($tkQ), 200, 'ddg-lite-results.html'));
preg_match_all('#href="/read\.php\?url=([^"&]+)&amp;t=([0-9a-f]{24})"#', $p7, $tkm, PREG_SET_ORDER);
check('search results: reader links signed', count($tkm) > 0, true);
check('search results: every t valid for its own URL',
      count(array_filter($tkm, function ($m) { return !df_readtok_valid(urldecode(html_entity_decode($m[1])), $m[2]); })), 0);
check('search results: no unsigned reader link left',
      preg_match('#href="/read\.php\?url=[^"&]+"#', $p7), 0);
reset_ddg_state();
check('news/feeds (df_river) and HN links signed', [
      strpos((string)file_get_contents(__DIR__ . '/../public/lib.php'), "df_readtok_qs(\$link, true)") !== false,
      substr_count((string)file_get_contents(__DIR__ . '/../public/hn.php'), 'df_readtok_qs(')], [true, 2]);
$rv = df_river([['link' => 'https://news.example/a', 'title' => 'A story', 'desc' => '', 'source' => 'S', 'ts' => time()]], false);
check('df_river: link carries a valid t', (bool)preg_match('#/read\.php\?url=https%3A%2F%2Fnews\.example%2Fa&amp;t=([0-9a-f]{24})#', $rv, $rvm) && df_readtok_valid('https://news.example/a', $rvm[1]), true);

// --- reader items 7-8 (added 2026-11-12): text-mode link numbers, article parts --
$tl = json_decode(page_fn_cli('read.php', 'echo json_encode(rd_txt_number_links('
    . var_export('<p>See <a href="/read.php?url=https%3A%2F%2Fex.com%2Fa&amp;img=0">the first</a> and '
    . '<a href="#fn1">note</a> and <a href="/dl.php?url=https%3A%2F%2Fex.com%2Ff.zip">a file</a>'
    . '<a name="fn1"></a> and <a href="/read.php?url=https%3A%2F%2Fex.com%2Fb"><img src="/i.gif"></a>.</p>', true)
    . '));'), true);
check('txt links: numbered in text', strip_tags($tl[0] ?? ''), 'See the first[1] and note and a file[2] and .');
check('txt links: references are absolute reader URLs in text mode; dl stays dl', [preg_replace('/&t=[0-9a-f]+$/', '', $tl[1][0] ?? ''), $tl[1][1] ?? null], [
    'http://duckfind.com/read.php?url=' . urlencode('https://ex.com/a') . '&fmt=txt',
    'http://duckfind.com/dl.php?url=https%3A%2F%2Fex.com%2Ff.zip']);
check('txt links: in-page #anchors and image-only links not listed; none unnumbered', $tl[2] ?? null, 0);
// signed since 2026-11-12 (a text browser can't pass the picture check); dl links are not
preg_match('/&t=([0-9a-f]+)$/', $tl[1][0] ?? '', $tlm);
// validated in a child like the one that signed it (same signing secret; this
// process switched cache_dir, and with it the secret file, at the top)
check('txt links: reader references signed with a valid token', page_fn_cli('read.php',
    'echo df_readtok_valid("https://ex.com/a", ' . var_export($tlm[1] ?? '', true) . ') ? "valid" : "bad";'), 'valid');
check('txt links: dl reference not signed', strpos($tl[1][1] ?? '', '&t=') === false, true);
$many = '';
for ($i = 1; $i <= 160; $i++) $many .= '<a href="/read.php?url=https%3A%2F%2Fex.com%2F' . $i . '">l' . $i . '</a> ';
$tm = json_decode(page_fn_cli('read.php', 'echo json_encode(rd_txt_number_links(' . var_export($many, true) . '));'), true);
check('txt links: capped at 150, the rest counted', [count($tm[1] ?? []), $tm[2] ?? null, strpos($tm[0] ?? '', 'l151[') === false], [150, 10, true]);
$ty = json_decode(page_fn_cli('read.php', 'echo json_encode(rd_txt_number_links(' . var_export('<a href="/read.php?url=https%3A%2F%2Fex.com%2Fa">x</a>', true) . ', "1999"));'), true);
check('txt links: Wayback year carried', preg_replace('/&t=[0-9a-f]+$/', '', $ty[1][0] ?? ''), 'http://duckfind.com/read.php?url=' . urlencode('https://ex.com/a') . '&fmt=txt&year=1999&raw=0');
// read.php in text mode end to end (cached raw page)
$tu = 'https://txt.example/a-' . getmypid();
$tpage = '<html><head><title>Txt</title></head><body><article><h1>Txt</h1><p>' . str_repeat('Plenty of words here for the extractor. ', 20)
       . 'Read <a href="https://txt.example/next">the next part</a> now.</p></article></body></html>';
$to = page_cli('read.php', 'df_cache_put(' . var_export('raw:' . $tu, true) . ', serialize(["status" => 200, "ctype" => "text/html", "url" => ' . var_export($tu, true) . ', "body" => ' . var_export($tpage, true) . ']));'
    . '$_GET = ["url" => ' . var_export($tu, true) . ', "fmt" => "txt"];');
check('txt mode: link numbered and References list printed',
      [strpos($to, 'the next part[1]') !== false, strpos($to, "References\n\n 1. http://duckfind.com/read.php?url=" . urlencode('https://txt.example/next') . '&fmt=txt') !== false], [true, true]);

// pagination
$blk = fn(int $n, string $w = 'Paragraph') => str_repeat('<p>' . $w . ' text that fills a part of the article nicely. </p>', $n);
$pg = json_decode(page_fn_cli('read.php', 'echo json_encode(rd_paginate(' . var_export($blk(40), true) . ', 1000));'), true);
check('paging: splits into several parts', count($pg ?? []) > 1, true);
check('paging: parts join back to the original', implode('', $pg ?? []), $blk(40));
check('paging: every part ends at a block boundary', count(array_filter($pg ?? [], fn($p) => !preg_match('#</p>\s*$#', $p))), 0);
check('paging: parts stay within the limit when blocks are small', max(array_map('strlen', $pg ?? [''])) <= 1000, true);
$pre = $blk(5) . '<pre>' . str_repeat("line of code inside a pre block\n", 80) . '</pre>' . '<table><tr><td>' . $blk(10, 'Cell') . '</td></tr></table>' . $blk(20);
$pp = json_decode(page_fn_cli('read.php', 'echo json_encode(rd_paginate(' . var_export($pre, true) . ', 800));'), true);
check('paging: never cuts inside pre or table',
      count(array_filter($pp ?? [], fn($p) => substr_count($p, '<pre>') !== substr_count($p, '</pre>') || substr_count($p, '<table>') !== substr_count($p, '</table>'))), 0);
check('paging: oversized pre kept whole in one part', count(array_filter($pp ?? [], fn($p) => strpos($p, '<pre>') !== false)), 1);
$list = '<ul>' . str_repeat('<li><p>Item text that is long enough to count for something.</p></li>', 40) . '</ul>' . $blk(10);
$pl = json_decode(page_fn_cli('read.php', 'echo json_encode(rd_paginate(' . var_export($list, true) . ', 500));'), true);
check('paging: never cuts inside a list', count(array_filter($pl ?? [], fn($p) => substr_count($p, '<ul>') !== substr_count($p, '</ul>'))), 0);
check('paging: off (0) and short content unchanged', json_decode(page_fn_cli('read.php', 'echo json_encode([rd_paginate(' . var_export($blk(40), true) . ', 0), rd_paginate("<p>x</p>", 1000)]);'), true),
      [[$blk(40)], ['<p>x</p>']]);
$ol = '<p>Intro paragraph that is fairly short.</p><ol start="3">' . str_repeat('<li><p>A long footnote with enough words to need room on the page.</p></li>', 60) . '</ol>';
$po = json_decode(page_fn_cli('read.php', 'echo json_encode(rd_paginate(' . var_export($ol, true) . ', 1500));'), true);
check('paging: a long top-level list is cut between items', count($po ?? []) > 2, true);
check('paging: each list part balanced', count(array_filter($po ?? [], fn($p) => substr_count($p, '<ol') !== substr_count($p, '</ol>'))), 0);
preg_match('#<ol start="(\d+)">#', $po[1] ?? '', $osm);
$firstItems = substr_count($po[0] ?? '', '<li>');
check('paging: reopened <ol> continues numbering (start = 3 + items so far)', (int)($osm[1] ?? 0), 3 + $firstItems);
check('paging: all list items kept', array_sum(array_map(fn($p) => substr_count($p, '<li>'), $po ?? [])), 60);
$tail = $blk(30) . '<p>x</p>';
$pt = json_decode(page_fn_cli('read.php', 'echo json_encode(rd_paginate(' . var_export($tail, true) . ', 1700));'), true);
check('paging: a tiny last part is folded into the one before', min(array_map('strlen', $pt ?? ['']) ) >= intdiv(1700, 8), true);
$lp = json_decode(page_fn_cli('read.php', 'echo json_encode(rd_link_parts(["<p><a href=\"#n2\">to note</a> <a href=\"#n1\">here</a><a name=\"n1\"></a></p>", "<p><a name=\"n2\"></a>note</p>"], fn($n) => "/read.php?url=X&amp;pt=" . $n));'), true);
check('paging: in-page link to another part goes to that part; same-part link unchanged',
      [strpos($lp[0] ?? '', '<a href="/read.php?url=X&amp;pt=2#n2">') !== false, strpos($lp[0] ?? '', '<a href="#n1">') !== false], [true, true]);
// read.php end to end: part navigation, parameters carried, pt clamped, off switch
$pu = 'https://pages.example/long-' . getmypid();
$ppage = '<html><head><title>Long one</title></head><body><article><h1>Long one</h1>' . $blk(800, 'Body') . '</article></body></html>';
$pseed = 'df_cache_put(' . var_export('raw:' . $pu, true) . ', serialize(["status" => 200, "ctype" => "text/html", "url" => ' . var_export($pu, true) . ', "body" => ' . var_export($ppage, true) . ']));';
$tokp = df_readtok($pu);
$p1 = page_cli('read.php', $pseed . '$_GET = ["url" => ' . var_export($pu, true) . ', "img" => "0", "t" => ' . var_export($tokp, true) . '];');
preg_match('#Page 1 of (\d+)#', $p1, $pm);
check('paging page: first part shows Page 1 of N (N > 1)', (int)($pm[1] ?? 0) > 1, true);
check('paging page: Next link carries url, img=0, t and pt=2',
      strpos($p1, '<a href="/read.php?url=' . htmlspecialchars(urlencode($pu), ENT_QUOTES) . '&amp;img=0&amp;raw=0&amp;t=' . $tokp . '&amp;pt=2">Next &gt;</a>') !== false, true);
check('paging page: no Previous on part 1; nav shown twice', [strpos($p1, '&lt; Previous</a>') === false, substr_count($p1, 'Page 1 of ')], [true, 2]);
$p2 = page_cli('read.php', $pseed . '$_GET = ["url" => ' . var_export($pu, true) . ', "pt" => "2"];');
check('paging page: part 2 has Previous back to part 1 (no pt)', strpos($p2, '<a href="/read.php?url=' . htmlspecialchars(urlencode($pu), ENT_QUOTES) . '&amp;raw=0">&lt; Previous</a>') !== false, true);
$p99 = page_cli('read.php', $pseed . '$_GET = ["url" => ' . var_export($pu, true) . ', "pt" => "99"];');
check('paging page: pt out of range clamps to the last part', strpos($p99, 'Page ' . ($pm[1] ?? 'x') . ' of ' . ($pm[1] ?? 'x')) !== false, true);
$poff = page_cli('read.php', $pseed . '$GLOBALS["DF_CFG"]["read_page_bytes"] = 0; $_GET = ["url" => ' . var_export($pu, true) . '];');
check('paging page: read_page_bytes 0 = one page, whole article', [strpos($poff, 'Page 1 of') === false, substr_count($poff, 'Body text that fills')], [true, 800]);
check('example config: read_page_bytes default', df_cfg('read_page_bytes'), 32768);



// --- signed in-page links + text-browser busy page (added 2026-11-12) -----------
$ip = page_fn_cli('read.php', 'echo render_node((function () { $d = new DOMDocument(); '
    . '$d->loadHTML(\'<?xml encoding="UTF-8" ?><div><p><a href="https://ex.org/story">a story</a></p></div>\'); '
    . 'return $d->getElementsByTagName("div")->item(0); })(), "https://ex.org/");');
preg_match('/read\.php\?url=https%3A%2F%2Fex\.org%2Fstory[^"]*&amp;t=([0-9a-f]+)/', $ip, $ipm);
check('in-page reader link carries a valid read token', page_fn_cli('read.php',
    'echo df_readtok_valid("https://ex.org/story", ' . var_export($ipm[1] ?? '', true) . ') ? "valid" : "bad";'), 'valid');
check('text browser UA detected', [
    (function () { $_SERVER['HTTP_USER_AGENT'] = 'Lynx/2.9.2 libwww-FM/2.14'; return df_text_browser(); })(),
    (function () { $_SERVER['HTTP_USER_AGENT'] = 'w3m/0.5.3'; return df_text_browser(); })(),
    (function () { $_SERVER['HTTP_USER_AGENT'] = 'ELinks/0.13 (textmode; Linux)'; return df_text_browser(); })(),
    (function () { $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/3.0 (Macintosh; I; PPC)'; return df_text_browser(); })(),
], [true, true, true, false]);
unset($_SERVER['HTTP_USER_AGENT']);
$tbPage = function (string $ua) use ($readSpent, $rq) {
    return page_cli('read.php', $readSpent . '$_SERVER["HTTP_USER_AGENT"] = ' . var_export($ua, true) . ';'
        . '$_GET = ["url" => ' . var_export($rq . '-tb', true) . ']; $_SERVER["REQUEST_URI"] = "/read.php?url=x";');
};
$tbL = $tbPage('Lynx/2.9.2 libwww-FM/2.14');
check('over the cap, Lynx: plain busy page, no picture check', [strpos($tbL, "\nCODE=503") !== false, strpos($tbL, 'The reader is busy') !== false, strpos($tbL, 'action="/captcha.php"') === false], [true, true, true]);
$tbN = $tbPage('Mozilla/3.0 (Macintosh; I; PPC)');
check('over the cap, Netscape: still the picture check', strpos($tbN, 'action="/captcha.php"') !== false, true);

// --- HN, watch, guestbook fixes (added 2026-11-12) ---------------------------
// HN thread: every item seeded into the cache where http_get_cached/hn_items read
// it, so no network. Story 9000001 has 5 descendants; 4 are loaded, one of them
// deleted with a reply; a 5-deep reply chain; a code block.
$hnSeed = function (array $items): string {
    $s = '';
    foreach ($items as $it) {
        $u = 'https://hacker-news.firebaseio.com/v0/item/' . $it['id'] . '.json';
        $s .= 'df_cache_put(' . var_export('raw:' . $u, true) . ', serialize(["status" => 200, "ctype" => "application/json", "url" => '
            . var_export($u, true) . ', "body" => ' . var_export(json_encode($it), true) . ']));';
    }
    return $s;
};
$hnItems = [
    ['id' => 9000001, 'type' => 'story', 'title' => 'Test story', 'by' => 'op', 'time' => time() - 60, 'score' => 3, 'descendants' => 9,
     'kids' => [9000002, 9000003]],
    ['id' => 9000002, 'type' => 'comment', 'by' => 'alice', 'time' => time() - 50,
     'text' => "<p>Look:<p><pre><code>line one\n  line two\nline three</code></pre><p>done", 'kids' => [9000004]],
    ['id' => 9000003, 'type' => 'comment', 'deleted' => true, 'time' => time() - 40, 'kids' => [9000005]],
    ['id' => 9000005, 'type' => 'comment', 'by' => 'carol', 'time' => time() - 30, 'text' => 'reply under a deleted comment'],
    ['id' => 9000004, 'type' => 'comment', 'by' => 'd1', 'time' => time() - 20, 'text' => 'depth 1', 'kids' => [9000006]],
    ['id' => 9000006, 'type' => 'comment', 'by' => 'd2', 'time' => time() - 20, 'text' => 'depth 2', 'kids' => [9000007]],
    ['id' => 9000007, 'type' => 'comment', 'by' => 'd3', 'time' => time() - 20, 'text' => 'depth 3', 'kids' => [9000008]],
    ['id' => 9000008, 'type' => 'comment', 'by' => 'd4', 'time' => time() - 20, 'text' => 'depth 4', 'kids' => [9000009]],
    ['id' => 9000009, 'type' => 'comment', 'by' => 'd5', 'time' => time() - 20, 'text' => 'depth 5 deepest'],
];
$hn = page_cli('hn.php', $hnSeed($hnItems) . '$_GET = ["id" => "9000001"];');
check('hn: thread renders from the cache', [strpos($hn, 'Test story') !== false, strpos($hn, 'depth 5 deepest') !== false], [true, true]);
check('hn: deleted comment kept as a placeholder with its reply', [strpos($hn, '[deleted]') !== false, strpos($hn, 'reply under a deleted comment') !== false], [true, true]);
check('hn: code block keeps its line breaks in <pre>, not inside <p>', [
      (bool)preg_match("#<pre>line one\n  line two\nline three</pre>#", $hn), strpos($hn, '<p><pre>') === false], [true, true]);
$hnDepth = 0; $hnMax = 0;
foreach (preg_split('#(<dl><dd>|</dd></dl>)#', $hn, -1, PREG_SPLIT_DELIM_CAPTURE) as $tok) {
    if ($tok === '<dl><dd>') $hnMax = max($hnMax, ++$hnDepth); elseif ($tok === '</dd></dl>') $hnDepth--;
}
check('hn: nesting is <dl><dd>, at most 4 deep (5-deep chain), balanced, no blockquote', [
      strpos($hn, '<blockquote>') === false, $hnMax, $hnDepth, substr_count($hn, '<dl><dd>') === substr_count($hn, '</dd></dl>')], [true, 4, 0, true]);
check('hn: honest truncation note, no link to news.ycombinator.com', [
      strpos($hn, '(showing 7 of 9 comments -- reload to load more)') !== false, strpos($hn, 'news.ycombinator.com') === false], [true, true]);
// hn_items: all cache hits -> no network, ids in, items out
$hi = page_fn_cli('hn.php', '$GLOBALS["DF_CFG"]["cache_dir"] = ' . var_export($tmpCache, true) . ';'
    . 'echo json_encode(array_keys(hn_items([9000004, 9000006, 0], microtime(true) + 5)));');
check('hn_items: cached items returned without a fetch; bad ids skipped', json_decode(substr($hi, strrpos($hi, '[')), true), [9000004, 9000006]);

// watch: relay unreachable (refused port) -- no homelab, no relay
$wRelay = '$GLOBALS["DF_CFG"]["relay_url"] = "http://127.0.0.1:9"; $GLOBALS["DF_CFG"]["relay_secret"] = "x";';
$wId = page_fn_cli('watch.php', 'echo json_encode(array_map("watch_video_id", ['
    . '"https://www.youtube.com/watch?v=dQw4w9WgXcQ&si=TRACKME&t=42", "https://youtu.be/dQw4w9WgXcQ?si=TRACKME",'
    . '"https://www.youtube.com/shorts/dQw4w9WgXcQ", "https://m.youtube.com/embed/dQw4w9WgXcQ",'
    . '"https://www.youtube.com/results?search_query=x", "https://www.youtube.com/watch?v=short"]));');
check('watch: video id from every link shape; none from search/bad ids', json_decode(substr($wId, strrpos($wId, '[')), true),
      ['dQw4w9WgXcQ', 'dQw4w9WgXcQ', 'dQw4w9WgXcQ', 'dQw4w9WgXcQ', '', '']);
$w1 = page_cli('watch.php', $wRelay . '$_GET = ["url" => "https://youtu.be/dQw4w9WgXcQ?si=TRACKME", "profile" => "mpeg1"];');
check('watch: first unreachable poll -> wait page with attempt counters', [
      (bool)preg_match('#refresh" content="10;url=/watch\.php\?url=https%3A%2F%2Fwww\.youtube\.com%2Fwatch%3Fv%3DdQw4w9WgXcQ&amp;profile=mpeg1&amp;n=1&amp;t0=\d+&amp;u=1"#', $w1),
      strpos($w1, 'TRACKME') === false], [true, true]);
check('watch: inline script hidden from pre-JS browsers', (bool)preg_match('#<script><!--\n.*\n// --></script>#s', $w1), true);
$w3 = page_cli('watch.php', $wRelay . '$_GET = ["url" => "https://www.youtube.com/watch?v=dQw4w9WgXcQ", "profile" => "mpeg1", "n" => "2", "u" => "2", "t0" => (string)(time() - 30)];');
check('watch: 3rd unreachable poll -> could not convert (502), retry link starts over', [
      strpos($w3, "\nCODE=502") !== false, strpos($w3, 'Could not convert this video') !== false, strpos($w3, 'not answering') !== false,
      strpos($w3, 'watch%3Fv%3DdQw4w9WgXcQ&amp;profile=mpeg1">try again') !== false], [true, true, true, true]);
$wOld = page_cli('watch.php', $wRelay . '$_GET = ["url" => "https://www.youtube.com/watch?v=dQw4w9WgXcQ", "profile" => "mpeg1", "n" => "30", "u" => "0", "t0" => (string)(time() - 400)];');
check('watch: past 5 minutes -> gives up', [strpos($wOld, "\nCODE=502") !== false, strpos($wOld, 'far longer') !== false], [true, true]);
$wBad = page_cli('watch.php', $wRelay . '$_GET = ["url" => "https://www.youtube.com/results?search_query=cats"];');
check('watch: link with no video id refused', strpos($wBad, 'does not point at a single YouTube video') !== false, true);
// unknown relay status -> failed (a stub relay on loopback, stopped afterwards)
if (function_exists('proc_open')) {
    $stubDir = $tmpCache . '/relay-stub';
    @mkdir($stubDir, 0777, true);
    file_put_contents($stubDir . '/r.php', '<?php header("Content-Type: application/json"); echo json_encode(["status" => "exploded"]);');
    $port = 18000 + getmypid() % 1000;
    $srv = proc_open([PHP_BINARY, '-S', '127.0.0.1:' . $port, $stubDir . '/r.php'], [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pp);
    usleep(400000);
    $wf = page_cli('watch.php', '$GLOBALS["DF_CFG"]["relay_url"] = "http://127.0.0.1:' . $port . '"; $GLOBALS["DF_CFG"]["relay_secret"] = "x";'
        . '$_GET = ["url" => "https://www.youtube.com/watch?v=dQw4w9WgXcQ", "profile" => "mpeg1"];');
    proc_terminate($srv); proc_close($srv);
    check('watch: unknown relay status is a failure, not ready', [strpos($wf, "\nCODE=502") !== false, strpos($wf, 'reported a problem') !== false, strpos($wf, '<embed') === false], [true, true, true]);
}

// guestbook: refused post keeps the typed text; success redirects (PRG)
$gbDir = $tmpCache . '/gb-' . getmypid();
@mkdir($gbDir, 0777, true);
$gbSetup = function (string $pending) use ($gbDir) {
    return 'define("GB_PENDING", ' . var_export($pending, true) . '); define("GB_APPROVED", ' . var_export($gbDir . '/approved.jsonl', true) . ');'
         . '$_SERVER["REQUEST_METHOD"] = "POST";';
};
$g1 = page_cli('guestbook.php', $gbSetup($gbDir . '/pending.jsonl') . '$_POST = ["name" => "Ann <b>", "msg" => ""];');
check('guestbook: error keeps the typed name (escaped)', [strpos($g1, 'Please fill in both') !== false, strpos($g1, 'value="Ann &lt;b&gt;"') !== false], [true, true]);
$g2 = page_cli('guestbook.php', $gbSetup('/nonexistent-dir/pending.jsonl') . '$_POST = ["name" => "Bo", "msg" => "Hi from a Mac SE"];');
check('guestbook: failed save keeps name and message', [strpos($g2, 'could not be saved') !== false, strpos($g2, 'value="Bo"') !== false, strpos($g2, '>Hi from a Mac SE</textarea>') !== false], [true, true, true]);
$g3 = page_cli('guestbook.php', $gbSetup($gbDir . '/pending.jsonl') . '$_POST = ["name" => "Cy", "msg" => "Hello from Netscape 3"];'
    . 'register_shutdown_function(function () { foreach (headers_list() as $h) echo "\nHDR=" . $h; });');
check('guestbook: accepted post is saved and redirected (303, no form re-render)', [
      strpos((string)@file_get_contents($gbDir . '/pending.jsonl'), 'Hello from Netscape 3') !== false, strpos($g3, "\nCODE=303") !== false,
      strpos($g3, 'Sign the guestbook') === false], [true, true, true]);
check('guestbook: rate slot checked before, consumed only after acceptance (source order)', (function () {
    $src = (string)file_get_contents(__DIR__ . '/../public/guestbook.php');
    $check = strpos($src, "df_rate_ok('guestbook', 3, 3600, false)");
    $take  = strpos($src, "df_rate_ok('guestbook', 3, 3600);");
    return $check !== false && $take !== false && $take > $check;
})(), true);
$g4 = page_cli('guestbook.php', '$_GET = ["thanks" => "1"];');
check('guestbook: thank-you page after the redirect', strpos($g4, 'Thanks for signing') !== false, true);
check('about: guestbook retention and limit disclosed', strpos(about_html([]), 'keeps the name, message and date you sign with until they are removed') !== false, true);
// --- core fixes A3/A4/A5/A12/A18 (2026-11-12) -----------------------------------
// A3: a body as long as the fetch cap was cut off: never cached, and an old
// 3,000,000-byte stub is not served to a caller asking for more (pdf.php).
check('A3 capped body detected', [df_body_capped(['body' => str_repeat('x', 10)], 10), df_body_capped(['body' => 'x'], 10), df_body_capped(null, 10)], [true, false, false]);
$a3u = 'https://example.invalid/big-' . getmypid() . '.pdf';
df_cache_put('raw:' . $a3u, serialize(['status' => 200, 'ctype' => 'application/pdf', 'url' => $a3u, 'body' => '%PDF' . str_repeat('x', DF_FETCH_DEFAULT_CAP - 4)]));
check('A3 old 3 MB stub still served to a 3 MB caller (reader)', strlen((string)(http_get_cached($a3u, 604800)['body'] ?? '')), DF_FETCH_DEFAULT_CAP);
check('A3 old 3 MB stub NOT served to a 25 MB caller (pdf.php): refetched (here: unreachable host -> null)', http_get_cached($a3u, 604800, 25000000), null);
check('A3 wayback reuses the stub check', strpos((string)file_get_contents(__DIR__ . '/../public/lib.php'), "if (is_array(\$d) && !df_cached_stub(\$d, \$maxlen)) return \$d;\n    }\n    \$deadline") !== false, true);
check('A3 pdf_run: failed run with no output is null (not cached as "no text")', page_fn_cli('pdf.php',
    'var_export([pdf_run(["/bin/sh", "-c", "exit 1"]), pdf_run(["/bin/sh", "-c", "printf hi; exit 1"]), pdf_run(["/bin/sh", "-c", "exit 0"])]);'),
    var_export([null, 'hi', ''], true));
// A4: transparency is flattened onto the page background, not black.
check('A4 img_flatten: transparent -> white / dark bg, opaque kept, palette transparency too', page_fn_cli('img.php',
    '$t = imagecreatetruecolor(4, 4); imagealphablending($t, false); imagesavealpha($t, true);'
  . 'imagefill($t, 0, 0, imagecolorallocatealpha($t, 0, 0, 0, 127)); imagesetpixel($t, 1, 1, imagecolorallocate($t, 255, 0, 0));'
  . '$rgb = function ($im, $x, $y) { $c = imagecolorat($im, $x, $y); return [($c >> 16) & 255, ($c >> 8) & 255, $c & 255]; };'
  . '$w = img_flatten($t, [255, 255, 255]); $d = img_flatten($t, [0x28, 0x2A, 0x36]);'
  . '$p = imagecreate(2, 2); $bg = imagecolorallocate($p, 0, 0, 0); imagecolortransparent($p, $bg);'
  . 'echo json_encode([$rgb($w, 0, 0), $rgb($w, 1, 1), $rgb($d, 0, 0), $rgb(img_flatten($p, [255, 255, 255]), 0, 0)]);'),
    json_encode([[255, 255, 255], [255, 0, 0], [0x28, 0x2A, 0x36], [255, 255, 255]]));
check('A4 image cache key carries the theme (img2:)', strpos((string)file_get_contents(__DIR__ . '/../public/img.php'), '$ckey = "img2:$mode:$w:" . ($bgDark ? \'d\' : \'l\')') !== false, true);
// A5: a _pob=1 URL without a valid cookie sets one and links to the clean URL;
// passing on a _pob=1 URL redirects to the clean one (no output here).
function pob_clean_run(string $qs): string {
    return (string)shell_exec(escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg('$GLOBALS["argv"] = [];'
        . 'require ' . var_export(__DIR__ . '/../public/lib.php', true) . ';'
        . '$_SERVER["SCRIPT_NAME"] = "/index.php"; $_SERVER["QUERY_STRING"] = ' . var_export($qs, true) . '; echo df_pob_clean_url();') . ' 2>&1');
}
check('A5 clean url drops _pob only', [pob_clean_run('q=x&_pob=1'), pob_clean_run('_pob=1'), pob_clean_run('q=a&_pob=1&s=10')], ['/?q=x', '/', '/?q=a&s=10']);
$a5 = pob_gate_run($modern, [], ['_pob' => '1']);
check('A5 stale _pob URL: cookies page now offers Continue to the clean URL', [strpos($a5, 'Cookies are required') !== false, strpos($a5, '<a href="/read.php?url=x">Continue</a>') !== false], [true, true]);
check('A5 valid cookie on a _pob=1 URL: redirected to the clean URL (not rendered)', pob_gate_run($modern, ['df_pob' => 1], ['_pob' => '1']), '');
check('A5 valid cookie, clean URL: passes as before', pob_gate_run($modern, ['df_pob' => 1]), 'PASSED');
check('A5 legacy cookieless still passes', pob_gate_run('MacWeb/2.0 (Macintosh; I; 68K)'), 'PASSED');
// A12: the pager's back-trail.
check('A12 search_hist', page_fn_cli('index.php', 'echo json_encode([search_hist("0,12", 24), search_hist("0,12,30", 24), search_hist("x,5,3", 9), search_hist("", 10)]);'),
    json_encode([[0, 12], [0, 12], [5], []]));
$a12json = json_encode(['type' => 'search', 'web' => ['results' => array_map(function ($i) {
    return ['title' => "R$i", 'url' => "https://ex.org/$i", 'description' => 'd'];
}, range(1, 10))]]);
reset_ddg_state(); df_ddg_backoff_clear('brave');
// search_cli sets $_GET itself, so the offsets ride in via a small wrapper
function a12_search(string $s, string $h, string $json): string {
    $q = 'pager test ' . getmypid();
    $code = '$GLOBALS["argv"] = [];'
          . 'require ' . var_export(__DIR__ . '/../public/lib.php', true) . ';'
          . '$GLOBALS["DF_CFG"]["cache_dir"] = ' . var_export($GLOBALS['tmpCache'], true) . ';'
          . '$GLOBALS["DF_CFG"]["brave_api_key"] = "k";'
          . '$GLOBALS["DF_TEST_BRAVE"] = function ($u, $hh) { return ["status" => 200, "ctype" => "application/json", "url" => $u, "body" => ' . var_export($json, true) . ']; };'
          . '$_GET = ["q" => ' . var_export($q, true) . ', "s" => ' . var_export($s, true) . ($h !== '' ? ', "h" => ' . var_export($h, true) : '') . '];'
          . '$src = (string)file_get_contents(' . var_export(__DIR__ . '/../public/index.php', true) . ');'
          . '$src = preg_replace("/^require __DIR__ \\\\. \'\\\\/lib\\\\.php\';$/m", "", $src, 1);'
          . 'eval("?>" . $src);';
    return (string)shell_exec(escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg($code) . ' 2>/dev/null');
}
// offset 24 reached via 0 and 12 (a 12-result page); this page has 10 results,
// so the old rule (24 - 10) would have sent "previous" to 14
$pg = a12_search('24', '0,12', $a12json);
check('A12 previous goes to the offset actually came from (12), keeping the older trail', [strpos($pg, 's=12&amp;h=0">&lt; previous') !== false, strpos($pg, 's=14') === false], [true, true]);
check('A12 more carries the trail plus this offset', strpos($pg, 's=34&amp;h=0,12,24">more results') !== false, true);
$pg1 = a12_search('12', '0', $a12json);
// old rule: 12 - 10 = 2
check('A12 previous to the first page has no s (old rule gave s=2)', [(bool)preg_match('#href="/\?q=pager[^"&]*">&lt; previous#', $pg1), strpos($pg1, 's=2"') === false], [true, true]);
reset_ddg_state(); df_ddg_backoff_clear('brave');
// A18: bangs without an argument go to the tool's landing page.
check('A18 bang landing', page_fn_cli('index.php', 'echo json_encode([bang_landing("weather"), bang_landing("map"), bang_landing("define"), bang_landing("d"), bang_landing("ai"), bang_landing("news"), bang_landing("nosuch")]);'),
    json_encode(['/weather.php', '/map.php', '/define.php', '/define.php', '/ask.php', null, null]));
check('A18 wired before the redirect', strpos((string)file_get_contents(__DIR__ . '/../public/index.php'), "if (\$go === null && \$rest === '') \$go = bang_landing(\$bang);\n    if (\$go !== null)") !== false, true);

// --- news batch (added 2026-11-12): RDF, stale fallback, feed cap, mixing,
// HN comments, times, text versions, favicons, Reddit ------------------------
$rdf = '<?xml version="1.0"?><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" '
     . 'xmlns="http://purl.org/rss/1.0/" xmlns:dc="http://purl.org/dc/elements/1.1/">'
     . '<channel rdf:about="https://ex.org/"><title>Ex</title></channel>'
     . '<item rdf:about="https://ex.org/a"><title>RDF one</title><link>https://ex.org/a</link>'
     . '<description>First &lt;b&gt;item&lt;/b&gt;</description><dc:date>2026-11-12T10:00:00Z</dc:date></item>'
     . '<item rdf:about="https://ex.org/b"><title>RDF two</title><link>https://ex.org/b</link>'
     . '<dc:date>2026-11-11T09:30:00+00:00</dc:date></item></rdf:RDF>';
$rp = df_feed_parse($rdf);
check('feed RDF: items parsed', array_column($rp ?? [], 'title'), ['RDF one', 'RDF two']);
check('feed RDF: dc:date and description', [$rp[0]['ts'] ?? 0, $rp[0]['desc'] ?? ''], [gmmktime(10, 0, 0, 11, 12, 2026), 'First item']);
check('feed parse: not XML is null, XML without items is []', [df_feed_parse('not xml at all'), df_feed_parse('<rss><channel></channel></rss>')], [null, []]);
$hnRss = '<rss version="2.0"><channel><item><title>Show HN: a thing</title><link>https://thing.example/</link>'
       . '<pubDate>Thu, 12 Nov 2026 14:05:00 +0000</pubDate><comments>https://news.ycombinator.com/item?id=46012345</comments>'
       . '<description><![CDATA[<a href="https://news.ycombinator.com/item?id=46012345">Comments</a>]]></description></item>'
       . '<item><title>Future</title><link>https://f.example/</link><pubDate>Thu, 12 Nov 2099 00:00:00 +0000</pubDate></item>'
       . '</channel></rss>';
$hp = df_feed_parse($hnRss);
check('feed HN: "Comments" description dropped, comments URL kept', [$hp[0]['desc'] ?? null, $hp[0]['comments'] ?? null],
      ['', 'https://news.ycombinator.com/item?id=46012345']);
check('feed: future dates clamped to now', abs(($hp[1]['ts'] ?? 0) - time()) < 5, true);
check('hn item id from comments URL', [df_hn_item_id('https://news.ycombinator.com/item?id=46012345'),
      df_hn_item_id('https://news.ycombinator.com/item?id=1&x=2'), df_hn_item_id('https://evil.example/item?id=5')], [46012345, 0, 0]);
// stale fallback: a cached copy older than 30 min but under a day is served when
// the fetch fails (unresolvable host), and the failure is negative-cached
$stU = 'https://feed-dead-' . getmypid() . '.invalid/rss';
df_cache_put('feed2:' . $stU, serialize([['title' => 'Old but good', 'link' => 'https://ex.org/old', 'ts' => time() - 7200, 'desc' => '', 'img' => '', 'comments' => '']]));
touch(df_cache_path('feed2:' . $stU), time() - 7200);
$ff0 = df_daily_count('feedfail');
check('feed stale fallback: failed fetch serves the cached copy', array_column(df_feed_items($stU, 5, 2), 'title'), ['Old but good']);
check('feed stale fallback: failure counted and negative-cached', [df_daily_count('feedfail'), df_cache_get('feedfail:' . $stU, 600) !== null], [$ff0 + 1, true]);
check('feed stale fallback: negative cache serves stale without a fetch', array_column(df_feed_items($stU, 5, 2), 'title'), ['Old but good']);
check('feed stale fallback: no copy at all is []', df_feed_items('https://feed-none-' . getmypid() . '.invalid/rss', 5, 2), []);
// site-wide hourly feed cap: over it, the cached copy and no fetch
$cpU = 'https://feed-capped-' . getmypid() . '.invalid/rss';
df_cache_put('feed2:' . $cpU, serialize([['title' => 'Capped copy', 'link' => 'https://ex.org/c', 'ts' => 1, 'desc' => '', 'img' => '', 'comments' => '']]));
touch(df_cache_path('feed2:' . $cpU), time() - 7200);
$fc0 = df_daily_count('feedcapped');
$feedCapSaved = $GLOBALS['DF_CFG']['feed_hourly_cap'] ?? null;
$GLOBALS['DF_CFG']['feed_hourly_cap'] = 1;
df_hourly_inc_capped('feed', 1);
check('feed cap: over the hourly cap serves the cached copy', array_column(df_feed_items($cpU, 5, 2), 'title'), ['Capped copy']);
check('feed cap: refusal counted, no fetch attempted (no failure marker)', [df_daily_count('feedcapped'), df_cache_get('feedfail:' . $cpU, 600)], [$fc0 + 1, null]);
$GLOBALS['DF_CFG']['feed_hourly_cap'] = $feedCapSaved;
check('example config: feed_hourly_cap / news settings', [df_cfg('feed_hourly_cap'), df_cfg('news_favicons'), df_cfg('news_budget_seconds')], [200, true, 10]);
$secs = df_cfg('news_sections');
check('example config: 7 news sections incl. Sports and Business', [count($secs), isset($secs['Sports'], $secs['Business'])], [7, true]);
// fair mixing
$mixIn = [];
for ($i = 0; $i < 6; $i++) { $mixIn[] = ['src' => 'A', 'ts' => 1000 - $i]; $mixIn[] = ['src' => 'B', 'ts' => 900 - $i]; }
$mixIn[] = ['src' => 'C', 'ts' => 10];
$mx = df_feed_mix($mixIn, 3, 10);
$cnt = array_count_values(array_column($mx, 'src'));
check('feed mix: 10 items, C included, newest first', [count($mx), isset($cnt['C']), $mx[0]['ts'] >= $mx[9]['ts']], [10, true, true]);
check('feed mix: per-source cap honoured before filling', [min($cnt['A'], 9) >= 3, $cnt['C']], [true, 1]);
$mx2 = df_feed_mix(array_slice($mixIn, 0, 4), 3, 10);
check('feed mix: short sections keep all items', count($mx2), 4);
// text versions
check('npr text version', [df_text_version_url('https://www.npr.org/2026/11/12/nx-s1-6038940/some-story'),
      df_text_version_url('https://www.npr.org/2025/03/04/1234567/old-style'),
      df_text_version_url('https://www.bbc.com/news/x')],
      ['https://text.npr.org/nx-s1-6038940', 'https://text.npr.org/1234567', 'https://www.bbc.com/news/x']);
// river: time of day, HN comments link, NPR rewrite (signed), favicon
$rvItems = [
    ['title' => 'NPR story', 'link' => 'https://www.npr.org/2026/11/12/nx-s1-6038940/x', 'ts' => gmmktime(14, 5, 0, 11, 12, 2026),
     'desc' => '', 'img' => 'https://ex.org/i.jpg', 'src' => 'NPR', 'comments' => ''],
    ['title' => 'HN story', 'link' => 'https://thing.example/', 'ts' => gmmktime(9, 0, 0, 11, 12, 2026),
     'desc' => '', 'img' => 'https://ex.org/j.jpg', 'src' => 'Hacker News', 'comments' => 'https://news.ycombinator.com/item?id=46012345'],
];
$_COOKIE = ['df_img' => '1', 'df_mode' => 'color'];
$rvh = df_river($rvItems, true);
check('river: time of day in UTC', strpos($rvh, 'Nov 12 14:05 UTC') !== false, true);
check('river: HN comments link to duckfind HN', strpos($rvh, '<a href="/hn.php?id=46012345">comments</a>') !== false, true);
check('river: NPR item opens the text version, signed',
      (bool)preg_match('#/read\.php\?url=https%3A%2F%2Ftext\.npr\.org%2Fnx-s1-6038940&amp;t=([0-9a-f]+)#', $rvh, $rvm)
      && df_readtok_valid('https://text.npr.org/nx-s1-6038940', $rvm[1]), true);
check('river: items with an image show it, no favicon placeholder', strpos($rvh, 'fav.php') === false, true);
$rvNo = [['title' => 'No pic', 'link' => 'https://www.npr.org/2026/11/12/nx-s1-1/x', 'ts' => 0, 'desc' => '', 'img' => '', 'src' => 'NPR', 'comments' => ''],
         ['title' => 'Pic', 'link' => 'https://ex.org/p', 'ts' => 0, 'desc' => '', 'img' => 'https://ex.org/k.jpg', 'src' => 'Ex', 'comments' => '']];
$rvn = df_river($rvNo, false);
check('river: no image -> favicon placeholder (32px) in the picture column, signed per host',
      strpos($rvn, '<td width="96" valign="top"><center><a href="/read.php?url=') !== false
      && strpos($rvn, '<img src="/fav.php?h=www.npr.org&amp;t=' . df_fav_token('www.npr.org') . '" width="32" height="32"') !== false, true);
check('river: no inline 16px favicon next to the source any more', strpos($rvn, 'width="16" height="16"') === false, true);
$rvAllNo = df_river([$rvNo[0]], false);
check('river: picture column present even when no item has an image', strpos($rvAllNo, '<td width="96"') !== false, true);
$_COOKIE = ['df_img' => '0'];
check('river: no favicon with images off', strpos(df_river($rvItems, true), 'fav.php') === false, true);
$_COOKIE = ['df_img' => '1', 'df_mode' => 'ascii'];
check('river: no favicon in ascii mode', strpos(df_river($rvItems, true), 'fav.php') === false, true);
$_COOKIE = [];
// .ico decoding (real favicons: 32-bit BMP frames, 8-bit palette frames, PNG frames)
foreach (['physorg', 'oldvcr', 'aljazeera'] as $fx) {
    $g = df_ico_decode((string)file_get_contents(__DIR__ . '/fixtures/fav-' . $fx . '.ico'));
    $ok = $g !== null && imagesx($g) === 16 && imagesy($g) === 16;
    $opaque = 0;
    if ($ok) for ($y = 0; $y < 16; $y++) for ($x = 0; $x < 16; $x++) {
        if ((imagecolorat($g, $x, $y) >> 24 & 0x7F) < 127) $opaque++;
    }
    check("ico decode: $fx 16x16 frame with visible pixels", [$ok, $opaque > 20], [true, true]);
}
check('ico decode: junk is null', [df_ico_decode("\x00\x00\x01\x00\x01\x00junk"), df_ico_decode('')], [null, null]);
check('ico decode: tiny headers are rejected, not read past the end', df_ico_decode("\x00\x00\x01\x00\x01\x00" . str_repeat("\x10", 16)), null);
// fav.php: a wrong token gets a blank, fetches nothing; a cached icon is served
$favBad = page_cli('fav.php', '$_GET = ["h" => "nothing-' . getmypid() . '.example", "t" => "0000000000000000"];');
check('fav.php: bad token -> blank GIF, no fetch, no failure marker',
      [strncmp($favBad, 'GIF8', 4) === 0, df_cache_get('favfail:nothing-' . getmypid() . '.example', 86400)], [true, null]);
$favH = 'cached-' . getmypid() . '.example';
$seedGif = (function () { $im = imagecreate(16, 16); imagecolorallocate($im, 200, 0, 0); ob_start(); imagegif($im); return ob_get_clean(); })();
df_cache_put('fav:32:color:l:' . $favH, $seedGif);
$favOk = page_cli('fav.php', '$_GET = ["h" => ' . var_export($favH, true) . ', "t" => ' . var_export(df_fav_token($favH), true) . '];');
check('fav.php: valid token serves the cached icon', substr($favOk, 0, strlen($seedGif)) === $seedGif, true);
$favEv = page_cli('fav.php', '$_GET = ["h" => "../etc", "t" => ' . var_export(df_fav_token('../etc'), true) . '];');
check('fav.php: invalid host refused even with a matching token', strncmp($favEv, 'GIF8', 4) === 0 && strlen($favEv) < 200, true);
// Reddit RSS ended 2026-11-13: My Feeds refuses/skips Reddit feeds from then on
check('feeds: Reddit dead from 2026-11-13', page_fn_cli('feeds.php', 'echo json_encode(['
    . 'fd_reddit_dead("https://www.reddit.com/r/vintageapple/.rss", gmmktime(0, 0, 0, 11, 13, 2026)),'
    . 'fd_reddit_dead("https://www.reddit.com/r/vintageapple/.rss", gmmktime(12, 0, 0, 11, 12, 2026)),'
    . 'fd_reddit_dead("https://old.reddit.com/.rss", gmmktime(0, 0, 0, 1, 1, 2027)),'
    . 'fd_reddit_dead("https://example.com/feed", gmmktime(0, 0, 0, 1, 1, 2027))]);'), '[true,false,true,false]');


// --- tool pages fixes (added 2026-11-12) -------------------------------------
// Upstream answers are stubbed through $GLOBALS['DF_TEST_HTTP'] / ['DF_TEST_WX']
// in the child (page_cli); no network.
$tp = getmypid() . '-' . mt_rand();
function http_stub(array $map): string {
    // $map: url substring => [status, body] (or null for a failed fetch); first match wins
    return '$GLOBALS["DF_TEST_HTTP"] = function ($u) { foreach (' . var_export($map, true) . ' as $k => $v) {'
         . ' if (strpos($u, $k) !== false) return $v === null ? null : ["status" => $v[0], "ctype" => "application/json", "body" => $v[1], "url" => $u]; }'
         . ' return null; };';
}
// wiki: identifying UA; upstream 429 is "temporarily unavailable", not "no article"
$w1 = page_cli('wiki.php', http_stub(['rest_v1/page/summary' => [429, '{}'], 'opensearch' => [429, '{}']])
    . 'register_shutdown_function(function () { echo "\nUA=" . WIKI_UA; });'
    . '$_GET = ["q" => "Throttled ' . $tp . '"];');
check('wiki: 429 says temporarily unavailable', [strpos($w1, 'Wikipedia is temporarily unavailable') !== false, strpos($w1, 'No Wikipedia article found') === false], [true, true]);
check('wiki: identifying UA with the site URL', (bool)preg_match('#UA=DuckFind/1\.0 \(\+https?://#', $w1), true);
$w2 = page_cli('wiki.php', http_stub(['rest_v1/page/summary' => [404, '{"title":"Not found."}'], 'opensearch' => [200, '["x",[],[],[]]']])
    . '$_GET = ["q" => "Nonexistent ' . $tp . '"];');
check('wiki: a real 404 is still "no article"', strpos($w2, 'No Wikipedia article found') !== false, true);
// wiki: case-preserving cache key (WHO is not who)
$whoDis = json_encode(['title' => 'Who', 'type' => 'disambiguation', 'content_urls' => ['desktop' => ['page' => 'https://en.wikipedia.org/wiki/Who']]]);
$whoOrg = json_encode(['title' => 'World Health Organization', 'type' => 'standard', 'extract' => 'The WHO is a UN agency.',
                       'content_urls' => ['desktop' => ['page' => 'https://en.wikipedia.org/wiki/World_Health_Organization']]]);
$w3 = page_cli('wiki.php', 'df_cache_put("wikisum2:who' . $tp . '", ' . var_export($whoDis, true) . ');'
    . 'df_cache_put("wikisum2:WHO' . $tp . '", ' . var_export($whoOrg, true) . ');'
    . http_stub([]) . '$_GET = ["q" => "WHO' . $tp . '"];');
check('wiki: "WHO" is not served the cached "who" page', [strpos($w3, 'World Health Organization') !== false, strpos($w3, 'could mean more than one thing') === false], [true, true]);
check('wiki: "read the full article" link is signed', (bool)preg_match('#/read\.php\?url=https%3A%2F%2Fen\.wikipedia\.org%2Fwiki%2FWorld_Health_Organization&amp;t=[0-9a-f]{24}#', $w3), true);
// define: multi-word term uses %20 (rawurlencode); every entry shown; cached
$defLog = $GLOBALS['tmpCache'] . '/define-url-' . $tp;
$lead = json_encode([
    ['word' => 'lead', 'phonetics' => [['text' => '/led/']], 'meanings' => [['partOfSpeech' => 'noun', 'definitions' => [['definition' => 'A heavy metal.']]]]],
    ['word' => 'lead', 'phonetics' => [['text' => '/li:d/']], 'meanings' => [['partOfSpeech' => 'verb', 'definitions' => [['definition' => 'To guide or conduct.']]]]],
]);
$d1 = page_cli('define.php', '$GLOBALS["DF_TEST_HTTP"] = function ($u) { file_put_contents(' . var_export($defLog, true) . ', $u . "\n", FILE_APPEND);'
    . ' return ["status" => 200, "ctype" => "application/json", "url" => $u, "body" => ' . var_export($lead, true) . ']; };'
    . '$_GET = ["q" => "ice cream ' . $tp . '"];');
check('define: multi-word term sent as %20, not +', strpos((string)@file_get_contents($defLog), 'ice%20cream%20') !== false, true);
check('define: every entry rendered', [strpos($d1, 'A heavy metal.') !== false, strpos($d1, 'To guide or conduct.') !== false, strpos($d1, '(2)') !== false], [true, true, true]);
@unlink($defLog);
$d2 = page_cli('define.php', '$GLOBALS["DF_TEST_HTTP"] = function ($u) { file_put_contents(' . var_export($defLog, true) . ', "CALLED"); return null; };'
    . '$_GET = ["q" => "ice cream ' . $tp . '"];');
check('define: second lookup served from the cache (no upstream call)', [strpos($d2, 'To guide or conduct.') !== false, is_file($defLog)], [true, false]);
$d3 = page_cli('define.php', http_stub(['dictionaryapi' => [404, '{"title":"No Definitions Found"}']]) . '$_GET = ["q" => "zzqx' . $tp . '"];');
check('define: a real 404 is "no definition"', strpos($d3, 'No definition found') !== false, true);
// wiby: JSON endpoint, 1-based paging, previous link, <ol start>, no URL in snippet, signed links
$wj = json_encode(array_map(function ($i) { return ['URL' => "https://ex$i.example/", 'Title' => "Page $i", 'Snippet' => " Page $i about old Macs &#39;80s", 'Description' => '']; }, range(1, 12)));
$y1 = page_cli('wiby.php', http_stub(['wiby.me/json' => [200, $wj]]) . '$_GET = ["q" => "mac' . $tp . '"];');
check('wiby: first "more results" is p=2', strpos($y1, '/wiby.php?q=mac' . $tp . '&amp;p=2') !== false, true);
check('wiby: page 1 has no previous link', strpos($y1, '&lt; previous') === false, true);
check('wiby: snippet decoded (then escaped once), title not repeated',
      [strpos(html_entity_decode($y1, ENT_QUOTES), "about old Macs '80s") !== false, strpos($y1, '&amp;#39;') === false, strpos($y1, 'Page 1 about') === false], [true, true, true]);
check('wiby: reader links signed', (bool)preg_match('#/read\.php\?url=https%3A%2F%2Fex1\.example%2F&amp;raw=1&amp;t=[0-9a-f]{24}#', $y1), true);
$y2 = page_cli('wiby.php', http_stub(['wiby.me/json' => [200, $wj]]) . '$_GET = ["q" => "mac' . $tp . '", "p" => "2"];');
check('wiby: page 2 numbers from 13, previous goes to page 1, more goes to 3',
      [strpos($y2, '<ol start="13">') !== false, strpos($y2, 'href="/wiby.php?q=mac' . $tp . '">&lt; previous') !== false, strpos($y2, '&amp;p=3') !== false], [true, true, true]);
$y3 = page_cli('wiby.php', http_stub(['wiby.me/json' => [503, 'down']]) . '$_GET = ["q" => "mac' . $tp . '"];');
check('wiby: outage message', strpos($y3, 'Wiby is not answering') !== false, true);
// translate: names only in the bang form; unknown form target; case-insensitive codes
$tr = function (string $text, string $to, string $q) {
    return json_decode(page_fn_cli('translate.php', '$GLOBALS["argv"] = []; echo json_encode(tr_parse_request('
        . var_export($text, true) . ', ' . var_export($to, true) . ', ' . var_export($q, true) . ', $GLOBALS["langs"]));'), true);
};
check('translate: "looking forward to it" stays one English sentence', $tr('', '', 'I am looking forward to it'), ['I am looking forward to it', 'en', '']);
check('translate: "to french" (a name) picks French', $tr('', '', 'good morning to French'), ['good morning', 'fr', '']);
check('translate: "to he" is not Hebrew in the bang form', $tr('', '', 'give it to he')[1], 'en');
check('translate: form code any case', $tr('hello', 'ZH-HANS', '')[1], 'zh-Hans');
check('translate: unknown form target reported', $tr('hello', 'klingon', ''), ['hello', 'en', 'klingon']);
$trp = page_cli('translate.php', '$_GET = ["text" => "hello", "to" => "klingon"];');
check('translate: page says unknown language', strpos($trp, 'Unknown language: klingon') !== false, true);
// calc: numbers, units, currencies (no network: currency answers are cached/never reached)
$cl = function (string $q) {
    $o = page_cli('calc.php', '$_GET = ["q" => ' . var_export($q, true) . '];');
    $i = strpos($o, '<h2>');
    return trim(preg_replace('/\s+/', ' ', html_entity_decode(strip_tags(substr($o, $i, strpos($o, '<hr', $i + 1) - $i)), ENT_QUOTES, 'UTF-8')));
};
check('calc: decimal comma "1,5 km to m"', strpos($cl('1,5 km to m'), '= 1500 m') !== false, true);
check('calc: thousands comma "1,234 m to km"', strpos($cl('1,234 m to km'), '= 1.234 km') !== false, true);
check('calc: "1.2.3 km" rejected', strpos($cl('1.2.3 km to m'), 'Could not read the number') !== false, true);
check('calc: "1,5+1" = 2.5', strpos($cl('1,5+1'), '= 2.5') !== false, true);
check('calc: "1,234,567+1"', strpos($cl('1,234,567+1'), '= 1234568') !== false, true);
check('calc: 0x10 rejected', strpos($cl('0x10'), 'Hex numbers') !== false, true);
check('calc: 0^-1 is division by zero', strpos($cl('0^-1'), 'Division by zero') !== false, true);
check('calc: mph to kph (speed, no currency call)', strpos($cl('60 mph to kph'), '= 96.56064 km/h') !== false, true);
check('calc: fl oz', strpos($cl('5 fl oz to ml'), '= 147.86765 ml') !== false, true);
check('calc: plurals', [strpos($cl('2 kilometres to m'), '= 2000 m') !== false, strpos($cl('3 teaspoons to tbsp'), '= 1 tbsp') !== false,
                        strpos($cl('20 millimeters to cm'), '= 2 cm') !== false], [true, true, true]);
check('calc: tonne vs ton', [strpos($cl('1 tonne to kg'), '= 1000 kg') !== false, strpos($cl('1 ton to kg'), '= 907.18474 kg') !== false], [true, true]);
check('calc: bits/bytes', strpos($cl('16 bits to bytes'), '= 2 bytes') !== false, true);
check('calc: same currency', strpos($cl('100 usd to usd'), '= 100 USD') !== false, true);
check('calc: currency without ECB rates named, no API call', strpos($cl('100 usd to rub'), 'RUB is not one of the currencies') !== false, true);
check('calc: unknown unit, no currency lookup', strpos($cl('5 abc to xyz'), "Can't convert") !== false, true);
check('calc: Frankfurter v1 host', strpos((string)file_get_contents(__DIR__ . '/../public/calc.php'), "'https://api.frankfurter.dev/v1/latest?from='") !== false, true);
check('calc: unchanged basics', [strpos($cl('2+2*(14-3)^2'), '= 244') !== false, strpos($cl('-3^2'), '= -9') !== false, strpos($cl('72 f to c'), '22.222222') !== false], [true, true, true]);
// ftp: Latin-1 names visible; example host
check('ftp: Latin-1 filename converted', page_fn_cli('ftp.php', '$GLOBALS["argv"] = []; echo ftp_e("caf\xE9.txt");'), 'caf&#233;.txt');
check('ftp: example host is ftp.funet.fi, not the dead ftp.kernel.org',
      [strpos((string)file_get_contents(__DIR__ . '/../public/ftp.php'), "ftp://ftp.funet.fi/pub/") !== false,
       strpos((string)file_get_contents(__DIR__ . '/../public/ftp.php'), "urlencode('ftp://ftp.kernel.org") === false], [true, true]);

// --- weather: caching, NWS fallback, stale copy (added 2026-11-12) -------------
// Stub: url substring => [status, body] or null (failed fetch); first match wins.
function wx_stub(array $map, string $log = ''): string {
    return '$GLOBALS["DF_TEST_WX"] = function ($u) { '
         . ($log !== '' ? 'file_put_contents(' . var_export($log, true) . ', $u . "\n", FILE_APPEND); ' : '')
         . 'foreach (' . var_export($map, true) . ' as $k => $v) {'
         . ' if (strpos($u, $k) !== false) return $v === null ? null : ["status" => $v[0], "ctype" => "application/json", "body" => $v[1], "url" => $u]; }'
         . ' return null; };';
}
$wxT = getmypid() . '-' . mt_rand();
// each test gets its own coordinates: forecasts are cached per location
$geoUSat = function (float $lat) { return json_encode(['results' => [['name' => 'Anchorage', 'admin1' => 'Alaska', 'country' => 'United States', 'country_code' => 'US', 'latitude' => $lat, 'longitude' => -149.90028]]]); };
$geoUS = $geoUSat(61.21806);
$geoGB = json_encode(['results' => [['name' => 'London', 'admin1' => 'England', 'country' => 'United Kingdom', 'country_code' => 'GB', 'latitude' => 51.50853, 'longitude' => -0.12574]]]);
$geoEq = json_encode(['results' => [['name' => 'Equator Town', 'country' => 'Somewhere', 'country_code' => 'EC', 'latitude' => 0, 'longitude' => 0]]]);
$om = json_encode(['current' => ['temperature_2m' => 41.2, 'apparent_temperature' => 35, 'weather_code' => 3, 'wind_speed_10m' => 7, 'relative_humidity_2m' => 80],
                   'daily' => ['time' => ['2026-11-12', '2026-11-13'], 'weather_code' => [3, 61], 'temperature_2m_max' => [44, 46], 'temperature_2m_min' => [33, 35]]]);
$nwsPts = (string)file_get_contents(__DIR__ . '/fixtures/nws-points.json');
$nwsFc  = (string)file_get_contents(__DIR__ . '/fixtures/nws-forecast.json');
$nwsP0  = json_decode($nwsFc, true)['properties']['periods'][0];
$wx = function (string $place, string $stub, string $extra = '', string $u = 'f') {
    return page_cli('weather.php', $stub . $extra . '$_GET = ["q" => ' . var_export($place, true) . ', "u" => ' . var_export($u, true) . '];');
};
// (1) Open-Meteo answers -> Open-Meteo
$a1 = $wx("Anchorage $wxT-a", wx_stub(['geocoding-api' => [200, $geoUS], 'api.open-meteo.com' => [200, $om]]));
check('weather: Open-Meteo ok -> Open-Meteo', [strpos($a1, 'Data: <a href="https://open-meteo.com/">Open-Meteo') !== false, strpos($a1, '41&deg;F') !== false, strpos($a1, 'National Weather Service') === false], [true, true, true]);
// (2) Open-Meteo fails, US location -> NWS (real fixtures)
$a2 = $wx("Anchorage $wxT-b", wx_stub(['geocoding-api' => [200, $geoUSat(61.3)], 'api.open-meteo.com' => null,
                                       'api.weather.gov/points/' => [200, $nwsPts], 'api.weather.gov/gridpoints/' => [200, $nwsFc]]));
check('weather: OM fails + US -> NWS forecast', [strpos($a2, 'Forecast: <a href="https://www.weather.gov/">US National Weather Service') !== false,
      strpos($a2, $nwsP0['temperature'] . '&deg;F') !== false, strpos($a2, e($nwsP0['shortForecast'])) !== false, strpos($a2, 'As of') === false], [true, true, true, true]);
// (2b) NWS in Celsius: temperature and wind converted
$a2c = $wx("Anchorage $wxT-bc", wx_stub(['geocoding-api' => [200, $geoUSat(61.4)], 'api.open-meteo.com' => null,
                                         'api.weather.gov/points/' => [200, $nwsPts], 'api.weather.gov/gridpoints/' => [200, $nwsFc]]), '', 'c');
check('weather: NWS in Celsius converts temperature', strpos($a2c, (int)round(($nwsP0['temperature'] - 32) * 5 / 9) . '&deg;C') !== false, true);
check('weather: NWS wind in km/h for Celsius', [strpos($a2c, 'km/h') !== false, strpos($a2c, ' mph') === false], [true, true]);
// (3) Open-Meteo fails, non-US -> NWS never asked; no stale copy -> error
$wlog = $GLOBALS['tmpCache'] . '/wx-urls-' . $wxT;
$a3 = $wx("London $wxT-c", wx_stub(['geocoding-api' => [200, $geoGB], 'api.open-meteo.com' => null, 'api.weather.gov' => [200, $nwsPts]], $wlog));
check('weather: OM fails + non-US + no stale copy -> error, NWS not asked',
      [strpos($a3, 'Weather is temporarily unavailable') !== false, strpos((string)@file_get_contents($wlog), 'api.weather.gov') === false], [true, true]);
// (4) Open-Meteo fails, non-US, but a good copy from 2 h ago -> shown with "as of"
$lastGB = json_encode(['src' => 'om', 'data' => json_decode($om, true), 'at' => time() - 7200]);
$a4 = $wx("London $wxT-d", wx_stub(['geocoding-api' => [200, $geoGB], 'api.open-meteo.com' => null]),
          'df_cache_put("wxlast:51.5085,-0.1257:f", ' . var_export($lastGB, true) . ');');
check('weather: OM fails + non-US -> stale copy with "as of"', [strpos($a4, '41&deg;F') !== false, strpos($a4, 'As of ' . gmdate('H:i', time() - 7200) . ' UTC') !== false], [true, true]);
// (5) Open-Meteo and NWS both fail, US, stale copy -> stale
$a5 = $wx("Anchorage $wxT-e", wx_stub(['geocoding-api' => [200, $geoUSat(61.5)], 'api.open-meteo.com' => null, 'api.weather.gov' => [503, 'down']]),
          'df_cache_put("wxlast:61.5,-149.9003:f", ' . var_export(json_encode(['src' => 'om', 'data' => json_decode($om, true), 'at' => time() - 3600]), true) . ');'
          );
check('weather: OM and NWS both fail -> stale copy', [strpos($a5, 'As of') !== false, strpos($a5, '41&deg;F') !== false], [true, true]);
// (6) a fresh (under 30 min) Open-Meteo copy is used without any fetch
@unlink($wlog);
$a6 = $wx("London $wxT-f", wx_stub(['geocoding-api' => [200, $geoGB]], $wlog),
          'df_cache_put("wxlast:51.5085,-0.1257:f", ' . var_export(json_encode(['src' => 'om', 'data' => json_decode($om, true), 'at' => time() - 600]), true) . ');');
check('weather: fresh cached forecast, no forecast fetch', [strpos($a6, '41&deg;F') !== false, strpos($a6, 'As of') === false,
      strpos((string)@file_get_contents($wlog), '://api.open-meteo.com') === false], [true, true, true]);
// (7) geocode cached: second lookup of the same place makes no geocoder call
@unlink($wlog);
$wx("London $wxT-f", wx_stub(['api.open-meteo.com' => [200, $om]], $wlog));
check('weather: geocode cached 7 days', strpos((string)@file_get_contents($wlog), 'geocoding-api') === false, true);
// (8) latitude 0 is a real place
$a8 = $wx("Equator $wxT-g", wx_stub(['geocoding-api' => [200, $geoEq], 'api.open-meteo.com' => [200, $om]]));
check('weather: latitude 0 is found (isset, not empty)', [strpos($a8, 'Could not find') === false, strpos($a8, 'Equator Town') !== false], [true, true]);
// (9) US detection: country code, then boxes
check('weather: US detection', page_fn_cli('weather.php', '$GLOBALS["argv"] = []; echo json_encode([wx_is_us(["country_code" => "US", "latitude" => 0, "longitude" => 0]),'
    . ' wx_is_us(["country_code" => "PR", "latitude" => 18.4, "longitude" => -66.1]), wx_is_us(["country_code" => "CA", "latitude" => 45, "longitude" => -75]),'
    . ' wx_is_us(["latitude" => 21.3, "longitude" => -157.8]), wx_is_us(["latitude" => 48.8, "longitude" => 2.35])]);'),
      '[true,true,false,true,false]');
check('weather: NWS rows pair day/night', page_fn_cli('weather.php', '$GLOBALS["argv"] = []; echo json_encode(wx_nws_rows(['
    . '["name" => "Tonight", "isDaytime" => false, "temperature" => 30, "temperatureUnit" => "F", "shortForecast" => "Clear"],'
    . '["name" => "Friday", "isDaytime" => true, "temperature" => 50, "temperatureUnit" => "F", "shortForecast" => "Sunny"],'
    . '["name" => "Friday Night", "isDaytime" => false, "temperature" => 32, "temperatureUnit" => "F", "shortForecast" => "Cloudy"]], "f"));'),
      '[["Tonight","Clear",null,30],["Friday","Sunny",50,32]]');
check('map: lat/lon presence uses isset (lat 0 is real)', [substr_count((string)file_get_contents(__DIR__ . '/../public/map.php'), "empty(\$j[0]['lat'])"),
      substr_count((string)file_get_contents(__DIR__ . '/../public/map.php'), "empty(\$j2['results'][0]['latitude'])")], [0, 0]);

// The summary stays the LAST thing in this file: sections appended below an
// exit() never run (2026-11-12: two test sections had been silently skipped).

// news page cache key follows the source config (HK-47, 2026-11-12)
check('news cache key includes a config hash', (bool)preg_match("/'newspage:'.*\\\$vCfg;/", (string)file_get_contents(__DIR__ . '/../public/news.php')), true);
$nk = function (array $sec) { return substr(sha1(serialize([$sec, null])), 0, 8); };
check('news config hash changes with the sections', $nk(['A' => ['x' => 'u']]) !== $nk(['A' => ['x' => 'u'], 'B' => ['y' => 'v']]), true);

// fav.php placeholder (2026-11-12): a host with no icon gets the duck, at the asked size
$fpH = 'noicon-' . getmypid() . '.example';
df_cache_put('favfail:' . $fpH, '1');
$fp32 = page_cli('fav.php', '$_GET = ["h" => ' . var_export($fpH, true) . ', "t" => ' . var_export(df_fav_token($fpH), true) . '];');
$fp16 = page_cli('fav.php', '$_GET = ["h" => ' . var_export($fpH, true) . ', "t" => ' . var_export(df_fav_token($fpH), true) . ', "s" => "16"];');
$fpSize = function (string $out) { $i = @getimagesizefromstring(substr($out, 0, (int)strpos($out . "\nCODE=", "\nCODE="))); return $i ? [$i[0], $i[1]] : null; };
check('fav.php: no icon -> duck placeholder, 32x32 by default', $fpSize($fp32), [32, 32]);
check('fav.php: s=16 still 16x16', $fpSize($fp16), [16, 16]);
check('fav.php: placeholder is not a blank (has more than one colour)',
      (function ($g) { $im = @imagecreatefromstring($g); return $im ? imagecolorstotal($im) > 2 : false; })(substr($fp32, 0, (int)strpos($fp32 . "\nCODE=", "\nCODE="))), true);

// --- reader: xkcd adapter, hidden content, title captions (2026-11-12) ------------
$xkJson = json_encode(['num' => 303, 'safe_title' => 'Compiling', 'title' => 'Compiling', 'year' => '2007', 'month' => '8', 'day' => '15',
    'img' => 'https://imgs.xkcd.com/comics/compiling.png', 'alt' => "'Are you stealing those LCDs?' 'Yeah, but I'm doing it while my code compiles.'",
    'link' => '', 'transcript' => 'HIDDEN-TRANSCRIPT-TEXT']);
$xkSeed = 'df_cache_put("raw:https://xkcd.com/303/info.0.json", serialize(["status" => 200, "ctype" => "application/json", "url" => "https://xkcd.com/303/info.0.json", "body" => ' . var_export($xkJson, true) . ']));';
$xk = page_cli('read.php', $xkSeed . '$_GET = ["url" => "https://xkcd.com/303/"];');
check('xkcd: title from the JSON', strpos($xk, 'Compiling (xkcd 303)') !== false, true);
check('xkcd: hover joke shown as the caption', strpos($xk, 'stealing those LCDs?') !== false, true);
check('xkcd: comic image through img.php', strpos($xk, '/img.php?url=https%3A%2F%2Fimgs.xkcd.com%2Fcomics%2Fcompiling.png') !== false, true);
check('xkcd: Prev/Next go to neighbouring comics, signed', [
    (bool)preg_match('#url=https%3A%2F%2Fxkcd\.com%2F302%2F&amp;t=[0-9a-f]+">&lt; Prev#', $xk),
    (bool)preg_match('#url=https%3A%2F%2Fxkcd\.com%2F304%2F&amp;t=[0-9a-f]+">Next &gt;#', $xk)], [true, true]);
check('xkcd: no store ad, comic lists or transcript', [strpos($xk, 'Comics I enjoy') === false, strpos($xk, 'HIDDEN-TRANSCRIPT-TEXT') === false], [true, true]);
foreach (['https://xkcd.com' => true, 'https://xkcd.com/' => true, 'https://xkcd.com/303' => true, 'https://m.xkcd.com/303/' => true,
          'http://www.xkcd.com/303/' => true, 'https://xkcd.com/303/#x' => true, 'https://xkcd.com/about/' => false,
          'https://xkcd.com.evil.example/303/' => false, 'https://evilxkcd.com/303/' => false] as $xu => $want) {
    $xs = 'df_cache_put("raw:https://xkcd.com/' . (preg_match('#/(\d+)#', $xu, $xn) ? $xn[1] . '/' : '') . 'info.0.json", serialize(["status" => 200, "ctype" => "application/json", "url" => "x", "body" => ' . var_export($xkJson, true) . ']));';
    $got = page_fn_cli('read.php', $xs . 'echo rd_xkcd_page(' . var_export($xu, true) . ') !== null ? "y" : "n";');
    check('xkcd URL shape: ' . $xu, $got, $want ? 'y' : 'n');
}
// live bug 2026-11-12: with the renderer configured, the short adapter page
// triggered the render fallback and the rendered real page won on length.
$xkLog = $GLOBALS['tmpCache'] . '/xk-render-' . getmypid();
@unlink($xkLog);
$xkSeed1 = str_replace('xkcd.com/303/info.0.json', 'xkcd.com/1/info.0.json', $xkSeed);
$xkR = page_cli('read.php', $xkSeed1 . '$GLOBALS["DF_CFG"]["render_url"] = "https://relay.example.invalid/"; $GLOBALS["DF_CFG"]["relay_secret"] = "rs";'
    . '$GLOBALS["DF_TEST_RENDER"] = function ($e, $p, $h) { file_put_contents(' . var_export($xkLog, true) . ', "called"); '
    . 'return ["status" => 200, "body" => json_encode(["status" => "ok", "final_url" => "https://xkcd.com/1/", "html" => "<html><body><p>" . str_repeat("Selected Comics sidebar junk. ", 40) . "</p></body></html>", "truncated" => false, "ms" => 1])]; };'
    . '$_GET = ["url" => "https://xkcd.com/1/", "raw" => "0"];');
check('xkcd with the renderer on: adapter page kept, renderer never called', [
    is_file($xkLog), strpos($xkR, 'sidebar junk') === false, strpos($xkR, 'built by JavaScript') === false,
    strpos($xkR, '(xkcd 303)') !== false || strpos($xkR, '(xkcd 1)') !== false], [false, true, true, true]);
check('xkcd: non-comic xkcd URLs are read normally', page_fn_cli('read.php', 'echo json_encode([rd_xkcd_page("https://xkcd.com/about/") === null, rd_xkcd_page("https://example.com/303/") === null]);'), '[true,true]');
$hidHtml = '<html><head><title>T</title></head><body><article><p>' . str_repeat('Visible paragraph text here. ', 20) . '</p>'
         . '<div style="display: none">HIDDEN-A</div><div hidden>HIDDEN-B</div><p style="Visibility:Hidden">HIDDEN-C</p>'
         . '<p aria-hidden="true">ARIA-STAYS</p></article></body></html>';
$hid = page_fn_cli('read.php', 'echo extract_readable(' . var_export($hidHtml, true) . ', "https://ex.com/")[1];');
check('reader: display:none / hidden / visibility:hidden dropped; aria-hidden kept', [
    strpos($hid, 'HIDDEN-A') === false, strpos($hid, 'HIDDEN-B') === false, strpos($hid, 'HIDDEN-C') === false,
    strpos($hid, 'ARIA-STAYS') !== false, strpos($hid, 'Visible paragraph') !== false], [true, true, true, true, true]);
$capHtml = '<html><head><title>T</title></head><body><article><p>' . str_repeat('Words for the article body. ', 20) . '</p>'
         . '<p><img src="https://ex.com/a.png" alt="A chart" title="Sales doubled in 2025"></p>'
         . '<p><img src="https://ex.com/b.png" alt="Plain alt only"></p>'
         . '<p><img src="https://ex.com/c.png" alt="Same text" title="same text"></p></article></body></html>';
$cap = page_fn_cli('read.php', 'echo extract_readable(' . var_export($capHtml, true) . ', "https://ex.com/")[1];');
check('reader: image title that differs from alt becomes the caption; else the alt', [
    strpos($cap, '<i>Sales doubled in 2025</i>') !== false, strpos($cap, '<i>Plain alt only</i>') !== false,
    strpos($cap, '<i>Same text</i>') !== false], [true, true, true]);
check('news: blocked-from-bespin sources gone from the defaults', [
    strpos((string)file_get_contents(__DIR__ . '/../config.example.php'), 'nintendolife') === false,
    strpos((string)file_get_contents(__DIR__ . '/../config.example.php'), 'phys.org') === false,
    strpos((string)file_get_contents(__DIR__ . '/../config.example.php'), 'aljazeera') === false], [true, true, true]);

// Guard (2026-11-12): nothing may follow this summary. Checks appended after
// the final exit() never run and silently go uncounted; that hid 4 tests once.
(function () {
    $src = (string)file_get_contents(__FILE__);
    $at  = strrpos($src, 'echo "$pass passed, $fail failed');
    $tail = $at === false ? '' : substr($src, $at);
    check('run.php: no check() after the summary', preg_match('/\\bcheck\\s*\\(/', $tail), 0);
})();

echo "$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
