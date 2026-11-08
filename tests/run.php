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
function read_html(string $url, string $year = ''): string {
    $code = '$GLOBALS["argv"] = [];'
          . 'require ' . var_export(__DIR__ . '/../public/lib.php', true) . ';'
          . '$GLOBALS["DF_CFG"]["cache_dir"] = ' . var_export($GLOBALS['tmpCache'], true) . ';'
          . '$_GET = ["url" => ' . var_export($url, true) . ($year !== '' ? ', "year" => ' . var_export($year, true) : '') . '];'
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

// --- map lat/lon array params read as 0, not 1.0 -----------------------------
check('df_str array -> float 0', (float)df_str(['x']), 0.0);

echo "$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
