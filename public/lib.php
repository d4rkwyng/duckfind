<?php
// Shared helpers for DuckFind — a retro web search + reader.
// Output is plain HTML 3.2 with all non-ASCII as numeric entities,
// so it renders on browsers as old as Netscape 1 / IE2 / MacWeb.

// Load config.php (your local copy) if present, else config.example.php.
// Works whether files are flat in the web root or under public/.
$GLOBALS['DF_CFG'] = [];
foreach (['/../config.php', '/config.php', '/../config.example.php', '/config.example.php'] as $rel) {
    if (is_file(__DIR__ . $rel)) { $GLOBALS['DF_CFG'] = require __DIR__ . $rel; break; }
}
function df_cfg(string $key, $default = null) {
    return $GLOBALS['DF_CFG'][$key] ?? $default;
}

define('DUCKFIND_NAME',    (string)df_cfg('name', 'DuckFind'));
define('DUCKFIND_UA',      (string)df_cfg('user_agent', 'Mozilla/5.0 (compatible; DuckFind/1.0)'));
define('DUCKFIND_TIMEOUT', (int)df_cfg('timeout', 12));
// !ytsearch's local yt-dlp path -- shared so about.php can tell whether the
// feature is actually enabled without duplicating (and risking drift from)
// the path ytsearch.php itself checks.
define('DUCKFIND_YTDLP_BIN', '/opt/ytdlp-venv/bin/yt-dlp');

// The small "DuckFind" brand link every page's top nav form starts with,
// consistently colored the same way the homepage's big masthead logo already
// is (Find colored to match Mallard's own beak, sampled from the real
// artwork). Only the exact default name gets the color split -- a self-host
// that renamed itself via config has no "Duck"/"Find" substrings to split,
// so it falls back to a plain bold link instead of a broken partial match.
// $colored=false renders a plain link with no Duck/Find colour split -- used
// by the footer's small-print credit line, where the colour treatment is the
// masthead/header's identity, not a thing to repeat in size="1" fine print
// on every single page.
function df_brand_link(bool $colored = true): string {
    if (!$colored || DUCKFIND_NAME !== 'DuckFind') {
        return '<a href="/"><b>' . e(DUCKFIND_NAME) . '</b></a>';
    }
    // "Duck" needs its own explicit color too, not just "Find" -- without it,
    // only "Find" is colour-locked and "Duck" falls through to the browser's
    // normal link/vlink colouring, so the brand link turns solid purple (and,
    // once visited, loses the black/orange split entirely) instead of staying
    // on-brand. No way to also drop the underline without CSS (HTML 3.2 has
    // no text-decoration), so a visited brand link is still underlined -- just
    // no longer discoloured. "Duck"'s own color is theme-aware (plain black is
    // invisible against dark mode's #282A36 body background) -- same body
    // text colour df_body_colors() already uses for dark mode.
    $duckColor = df_dark() ? '#F8F8F2' : 'black';
    return '<a href="/"><b><font color="' . $duckColor . '">Duck</font><font color="#E88C22">Find</font></b></a>';
}

// Every page is served as charset=iso-8859-1 (old browsers), so browsers
// submit form fields in that charset (in practice windows-1252), not UTF-8:
// "café" arrives as the raw byte 0xE9. Left as-is, invalid UTF-8 makes
// htmlspecialchars(..., 'UTF-8') in e() return '' (the query silently
// vanishes from the page) and json_encode() return false. Valid UTF-8 (a
// modern browser that sends it anyway, or a pasted %C3%A9 URL) is untouched.
function df_utf8(string $s): string {
    if ($s === '' || mb_check_encoding($s, 'UTF-8')) return $s;
    $c = @mb_convert_encoding($s, 'UTF-8', 'Windows-1252');
    return ($c !== false && mb_check_encoding($c, 'UTF-8')) ? $c : mb_scrub($s, 'UTF-8');
}

// Array-typed input (?q[]=x) reads as empty, not as the literal word "Array"
// plus an "Array to string conversion" warning.
function df_input(string $key): string {
    if (isset($_GET[$key])) return is_string($_GET[$key]) ? trim(df_utf8($_GET[$key])) : '';
    if (PHP_SAPI === 'cli' && isset($GLOBALS['argv'][1])) return trim(df_utf8((string)$GLOBALS['argv'][1]));
    return '';
}

// Raw request value ($_POST/$_COOKIE/$_GET element) as a string: an array
// (name[]=x) is '' -- the same rule as df_input(), for the call sites that
// read a superglobal directly. A plain (string) cast turns it into "Array".
function df_str($v): string {
    return is_string($v) ? $v : '';
}

// ===========================================================================
// SSRF protection: DuckFind fetches arbitrary user-supplied URLs, so it must
// never be usable to reach internal/LAN/cloud-metadata hosts. We resolve DNS
// ourselves, reject any non-public IP, pin the connection to the validated IP
// (defeats DNS rebinding), re-validate every redirect hop, and allow only
// http/https.
// ===========================================================================

function df_ip_in_cidr(string $ip, string $cidr): bool {
    if (strpos($cidr, '/') === false) return false;
    [$subnet, $bits] = explode('/', $cidr, 2);
    $ipb = @inet_pton($ip); $sub = @inet_pton($subnet);
    if ($ipb === false || $sub === false || strlen($ipb) !== strlen($sub)) return false;
    $bits = (int)$bits; $bytes = intdiv($bits, 8); $rem = $bits % 8;
    if ($bytes > 0 && strncmp($ipb, $sub, $bytes) !== 0) return false;
    if ($rem > 0) {
        $mask = chr((0xff << (8 - $rem)) & 0xff);
        if ((($ipb[$bytes] ^ $sub[$bytes]) & $mask) !== "\x00") return false;
    }
    return true;
}

// True only for public, routable addresses.
function df_ip_is_public(string $ip): bool {
    if (filter_var($ip, FILTER_VALIDATE_IP) === false) return false;
    // blocks 10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, 0/8, 240/4, fc00::/7, ...
    if (filter_var($ip, FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) return false;
    // ranges filter_var misses — notably 100.64/10 (CGNAT *and Tailscale*)
    // 2002::/16 (6to4) and 2001::/32 (Teredo) embed an IPv4 address that a relay
    // may route to, so treat them as non-public outright rather than unwrapping.
    foreach (['100.64.0.0/10', '192.0.0.0/24', '198.18.0.0/15',
              '::ffff:0:0/96', '64:ff9b::/96', '2001:db8::/32',
              '2002::/16', '2001::/32'] as $cidr) {
        if (df_ip_in_cidr($ip, $cidr)) return false;
    }
    // unwrap IPv4-mapped IPv6 (::ffff:127.0.0.1 would otherwise dodge v4 checks)
    $bin = @inet_pton($ip);
    if ($bin !== false && strlen($bin) === 16
        && substr($bin, 0, 12) === "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff") {
        return df_ip_is_public(inet_ntop(substr($bin, 12)));
    }
    return true;
}

// Validate a URL for outbound fetching; returns [url, host, port, ip, scheme] or null.
function df_validate_url(string $url): ?array {
    $p = parse_url($url);
    if (!$p || !isset($p['scheme'], $p['host'])) return null;
    $scheme = strtolower($p['scheme']);
    if ($scheme !== 'http' && $scheme !== 'https') return null;
    $host = strtolower($p['host']);   // one canonical form for the regex, DNS and CURLOPT_RESOLVE
    $port = (int)($p['port'] ?? ($scheme === 'https' ? 443 : 80));
    if ($port < 1 || $port > 65535) return null;

    $ips = [];
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        $ips = [$host];
    } else {
        if (!preg_match('/^[a-z0-9._\-]+$/i', $host)) return null;   // reject odd hostnames
        foreach (@dns_get_record($host, DNS_A | DNS_AAAA) ?: [] as $rec) {
            if (!empty($rec['ip']))   $ips[] = $rec['ip'];
            if (!empty($rec['ipv6'])) $ips[] = $rec['ipv6'];
        }
        if (!$ips && ($h = @gethostbynamel($host))) $ips = $h;
    }
    if (!$ips) return null;
    foreach ($ips as $ip) if (!df_ip_is_public($ip)) return null;   // one private record => reject

    return ['url' => $url, 'host' => $host, 'port' => $port, 'ip' => $ips[0], 'scheme' => $scheme];
}

// Public fetch entry point: validates, follows up to 6 redirects (each re-validated).
// $ua overrides the browser user-agent for APIs whose policy requires an honest,
// identifying one (OpenStreetMap tiles, OSRM). $post, when non-null, sends the
// request as a text/plain POST with that body (DDG translate).
// $headers (added 2026-11-12, for API keys): extra request headers, replacing the
// default Accept headers. Sent on the FIRST hop only, so a redirect can never
// carry them (a key) to another host.
function http_get(string $url, int $maxlen = 3000000, string $ua = '', ?string $post = null, int $timeout = 0,
                  array $headers = []): ?array {
    // Single wall-clock budget across ALL redirect hops (not per-hop) so a chain
    // of slow 302s can't hold a worker 6 x the timeout. $timeout overrides the
    // default (used for cheap side fetches like og:image thumbnails).
    $deadline = microtime(true) + ($timeout > 0 ? $timeout : DUCKFIND_TIMEOUT);
    $hops = 0;
    while ($hops++ < 6) {
        $t = df_validate_url($url);
        if ($t === null) return null;
        if ($ua !== '') $t['ua'] = $ua;
        if ($post !== null) $t['post'] = $post;
        if ($headers && $hops === 1) $t['headers'] = $headers;
        $remain = $deadline - microtime(true);
        if ($remain <= 0.2) return null;                 // whole-request time budget spent
        $t['timeout'] = (int)ceil($remain);
        $r = df_fetch_once($t, $maxlen);
        if ($r === null) return null;
        if ($r['status'] >= 300 && $r['status'] < 400 && $r['location'] !== '') {
            $url = absolutize($t['url'], $r['location']);
            continue;
        }
        // 'url' is the final URL after redirects -- the right base for
        // resolving the body's relative links (see read.php)
        return ['body' => $r['body'], 'ctype' => $r['ctype'], 'status' => $r['status'], 'url' => $t['url']];
    }
    return null;
}

// Single request, no auto-redirect, pinned to the validated IP.
function df_fetch_once(array $t, int $maxlen): ?array {
    // curl is required (README): it's the only path that pins the validated IP,
    // so we never fall back to an un-pinned stream wrapper (DNS-rebinding risk).
    if (!function_exists('curl_init')) return null;

    $loc = ''; $buf = '';
    $cap = $maxlen > 0 ? $maxlen : 3000000;
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL            => $t['url'],
        CURLOPT_FOLLOWLOCATION => false,                 // we follow + re-validate manually
        CURLOPT_TIMEOUT        => $t['timeout'] ?? DUCKFIND_TIMEOUT,
        CURLOPT_CONNECTTIMEOUT => 8,
        CURLOPT_USERAGENT      => $t['ua'] ?? DUCKFIND_UA,
        CURLOPT_HTTPHEADER     => $t['headers'] ?? (isset($t['post'])
            ? ['Accept: */*', 'Content-Type: text/plain']
            : ['Accept: text/html,*/*', 'Accept-Language: en-US,en']),
        CURLOPT_ENCODING       => '',                    // gzip/deflate/br
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_PROTOCOLS      => CURLPROTO_HTTP | CURLPROTO_HTTPS,   // no file://, gopher://, ...
        CURLOPT_RESOLVE        => [$t['host'] . ':' . $t['port'] . ':' . $t['ip']],   // pin IP
    ] + (isset($t['post']) ? [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => (string)$t['post'],
    ] : []) + [
        CURLOPT_HEADERFUNCTION => function ($ch, $h) use (&$loc) {
            if (stripos($h, 'Location:') === 0) $loc = trim(substr($h, 9));
            return strlen($h);
        },
        // Stream to a buffer and hard-abort at the cap, so a malicious origin
        // can't stream hundreds of MB into memory before we'd truncate it.
        CURLOPT_WRITEFUNCTION  => function ($ch, $chunk) use (&$buf, $cap) {
            $buf .= $chunk;
            return strlen($buf) > $cap ? 0 : strlen($chunk);   // returning 0 aborts
        },
    ]);
    $ok    = curl_exec($ch);
    $errno = curl_errno($ch);
    $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $ctype  = (string)curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
    unset($ch);
    // CURLE_WRITE_ERROR (23) is our own cap abort — keep what we have; anything else fails.
    if ($ok === false && $errno !== CURLE_WRITE_ERROR) return null;
    return ['body' => substr($buf, 0, $cap), 'ctype' => $ctype, 'status' => $status, 'location' => $loc];
}

// ===========================================================================
// Disk cache: spares slow retro clients repeat fetches/conversions and keeps
// us polite to DuckDuckGo & origin servers. Plain files under a cache dir.
// ===========================================================================

function df_cache_path(string $key): string {
    $dir = (string)df_cfg('cache_dir', sys_get_temp_dir() . '/duckfind-cache');
    if (!is_dir($dir)) @mkdir($dir, 0700, true);   // not world-readable (cached fetched pages)
    $h = sha1($key);
    return $dir . '/' . substr($h, 0, 2) . '/' . $h;
}

function df_cache_get(string $key, int $ttl): ?string {
    $f = df_cache_path($key);
    if (is_file($f) && filemtime($f) > time() - $ttl) {
        $d = @file_get_contents($f);
        return $d === false ? null : $d;
    }
    return null;
}

function df_cache_del(string $key): void {
    @unlink(df_cache_path($key));
}

function df_cache_put(string $key, string $data): void {
    $f = df_cache_path($key);
    $sub = dirname($f);
    if (!is_dir($sub)) @mkdir($sub, 0700, true);   // match the 0700 root (not world-readable)
    @file_put_contents($f, $data, LOCK_EX);
    df_cache_gc();
}

// Cache housekeeping, no cron required, on ~1.5% of writes:
// 1. delete entries older than DF_CACHE_MAX_AGE, the longest TTL any caller
//    uses -- such a file can never be served again, and the about page tells
//    visitors cached pages are deleted within a month;
// 2. enforce a total-SIZE ceiling by evicting oldest-first. The
// size cap is the real defence: without it an attacker sending unique URLs
// (read.php caches up to 3MB each) could fill the disk, and a full disk makes
// the file-backed rate limiter fail OPEN — unlocking every other limit. Capping
// the cache keeps the disk from ever filling from this path.
//
// Previously also ran an unconditional 7-day age sweep regardless of a given
// entry's own configured TTL -- removed (2026-10-09, confirmed live: it had
// quietly undermined several endpoints' own longer TTLs the whole time, e.g.
// ebook.php's 30-day book-text cache was never actually living past 7 days;
// the whole cache directory had zero files older than a week). A stale entry
// past its real TTL is already treated as a miss by df_cache_get()'s own
// mtime check regardless of whether the file still physically exists.
// (But with no age sweep at all, a stale file -- e.g. a cached search-results
// page, which contains the query -- sat on disk until 8 GB of newer entries
// pushed it out, contradicting the about page's retention statement. Step 1
// restores an age sweep at the LONGEST TTL, so it can't cut any TTL short.)
const DF_CACHE_MAX_AGE = 31 * 86400;   // > ebook.php's 30-day TTL, the longest
function df_cache_gc(): void {
    $roll = function_exists('random_int')
        ? (function () { try { return random_int(1, 200); } catch (\Throwable $e) { return 0; } })()
        : mt_rand(1, 200);
    if ($roll === 0) return;
    $dir = (string)df_cfg('cache_dir', sys_get_temp_dir() . '/duckfind-cache');

    if ($roll > 3) return;                               // ~1.5%: size-cap sweep
    $cap = (int)df_cfg('cache_max_bytes', 8589934592);   // 8 GB default
    // Only the two-hex-char shard dirs df_cache_path() creates -- NOT the
    // sibling rl/ (rate-limit buckets + the AI/search daily-cap counters) or
    // pdftmp/ (in-flight poppler input). Evicting a daily_* counter under
    // cache pressure would silently reset the paid-AI cost cap.
    $files = glob($dir . '/[0-9a-f][0-9a-f]/*') ?: [];
    $total = 0; $meta = [];
    $expired = time() - DF_CACHE_MAX_AGE;
    foreach ($files as $f) {
        $s = @filesize($f); $m = @filemtime($f);
        if ($s === false || $m === false) continue;
        if ($m < $expired) { @unlink($f); continue; }   // past every TTL: dead weight
        $total += $s; $meta[$f] = [$m, $s];
    }
    if ($total <= $cap) return;
    uasort($meta, fn($a, $b) => $a[0] <=> $b[0]);        // oldest first
    $target = (int)($cap * 0.9);                         // evict down to 90% of cap
    foreach ($meta as $f => $ms) {
        if ($total <= $target) break;
        if (@unlink($f)) $total -= $ms[1];
    }
}

// Cached wrapper around http_get (raw page bytes + content-type). Only 2xx
// responses are cached — an upstream 404/429/500/anti-bot page must not get
// frozen in for the whole TTL (a throttle would otherwise mimic "not found"
// for hours). The UA is part of the key so two callers fetching one URL with
// different user-agents don't share an entry.
// A body as long as the fetch cap was cut off mid-transfer (df_fetch_once
// aborts at the cap). Never cache one: callers share the 'raw:'/'wb:' keys with
// different caps (read.php 3 MB, pdf.php 25 MB), so a 3 MB stub cached by the
// reader used to be served to pdf.php as the whole PDF -- "No selectable text"
// for a week (2026-11-12). A cached body of exactly the old default cap that a
// caller wants more of is treated as such a stub from before this fix.
const DF_FETCH_DEFAULT_CAP = 3000000;
function df_body_capped(?array $r, int $maxlen): bool {
    return $r !== null && $maxlen > 0 && strlen((string)($r['body'] ?? '')) >= $maxlen;
}
function df_cached_stub(array $d, int $maxlen): bool {
    return $maxlen > DF_FETCH_DEFAULT_CAP && strlen((string)($d['body'] ?? '')) === DF_FETCH_DEFAULT_CAP;
}
function http_get_cached(string $url, int $ttl, int $maxlen = 3000000, string $ua = ''): ?array {
    $key = 'raw:' . ($ua !== '' ? sha1($ua) . ':' : '') . $url;
    if ($ttl > 0 && ($c = df_cache_get($key, $ttl)) !== null) {
        $d = @unserialize($c, ['allowed_classes' => false]);
        if (is_array($d) && !df_cached_stub($d, $maxlen)) return $d;
    }
    $r = http_get($url, $maxlen, $ua);
    if ($ttl > 0 && df_cacheable_response($r) && !df_body_capped($r, $maxlen)) df_cache_put($key, serialize($r));
    return $r;
}

// Whether a fetched response may go in the disk cache (http_get_cached and
// df_wayback_get share this rule): only a real 2xx with a non-empty body -- an
// empty 200/204 shouldn't be frozen in for the TTL (it makes every later
// visitor re-hit any bug an empty body triggers downstream). Never a 202
// Accepted: it means "not done", and it is how DuckDuckGo's HTML endpoint is
// known to answer a rate-limited scraper (the duckduckgo_search library's
// "202 Ratelimit") -- cached, that would freeze a throttle page onto a query.
function df_cacheable_response(?array $r): bool {
    if ($r === null) return false;
    $st = (int)($r['status'] ?? 200);
    return $st >= 200 && $st < 300 && $st !== 202 && (string)($r['body'] ?? '') !== '';
}

// --- DuckDuckGo search canary (added 2026-11-07) ----------------------------
// When a DDG response parses to zero results, tell apart a genuine "no
// results" page from a page we can't read, so a DDG markup change or a bot
// challenge never shows up as an innocent "No results found":
//   'blocked' -- a non-200 status (DDG's challenge comes as 202) or its
//                anomaly-modal challenge markup
//   'markup'  -- a 200 page with none of the structural containers every real
//                DDG HTML results page has (div#links.results, the
//                serp__results wrapper, the search form input). Checked against
//                real 200 responses fetched from bespin 2026-11-07.
//   'ok'      -- containers present, so zero results really means none found
// Only call it when parsing found zero results.
function df_ddg_page_kind(string $html, int $status): string {
    if ($status !== 200 || stripos($html, 'anomaly-modal') !== false) return 'blocked';
    $markers = 0;
    if (preg_match('/<div[^>]*\bid=["\']links["\']/i', $html)) $markers++;
    if (stripos($html, 'serp__results') !== false) $markers++;
    if (stripos($html, 'search_form_input_homepage') !== false) $markers++;
    return $markers >= 2 ? 'ok' : 'markup';
}

// Unwrap a DDG result href to its real destination. Results come as DDG
// redirect links (//duckduckgo.com/l/?uddg=<encoded url>&rut=...) on both the
// html and lite endpoints; plain absolute or protocol-relative links pass
// through. Anything else (relative paths, javascript:, ...) returns ''.
function ddg_real_url(string $href): string {
    if ($href === '') return '';
    if (strpos($href, 'uddg=') !== false) {
        parse_str(parse_url($href, PHP_URL_QUERY) ?? '', $qs);
        // only accept an http(s) destination — a javascript:/data: uddg value
        // has a host and would survive the parsers' host check, then land raw in
        // the "direct" link (defence-in-depth; DDG can't emit such a value)
        if (!empty($qs['uddg']) && preg_match('#^https?://#i', (string)$qs['uddg'])) return $qs['uddg'];
    }
    if (strpos($href, '//') === 0) return 'https:' . $href;
    if (preg_match('#^https?://#', $href)) return $href;
    return '';
}

// --- DuckDuckGo Lite fallback (added 2026-11-08) ------------------------------
// index.php falls back to lite.duckduckgo.com/lite/ when the html endpoint's
// canary says 'blocked' or 'markup'. Lite is a table layout; per real pages
// fetched from bespin 2026-11-07 (tests/fixtures/ddg-lite-*.html) each web
// result is:
//   <tr>...<td><a href="//duckduckgo.com/l/?uddg=..." class='result-link'>Title</a></td></tr>
//   <tr><td>&nbsp;</td><td class='result-snippet'>Snippet</td></tr>   (optional row)
//   <tr><td>&nbsp;</td><td><span class='link-text'>host/path</span></td></tr>
// The zero-click box above the results has plain links with no class, so it
// is never picked up. Returns the same shape as parse_ddg().
function parse_ddg_lite(string $html): array {
    $out = [];
    if ($html === '') return $out;
    $dom = new DOMDocument();
    libxml_use_internal_errors(true);
    $dom->loadHTML('<?xml encoding="UTF-8" ?>' . $html);
    libxml_clear_errors();
    $xp = new DOMXPath($dom);
    $anchors = $xp->query('//a[contains(concat(" ", normalize-space(@class), " "), " result-link ")]');
    foreach ($anchors as $a) {
        $url = ddg_real_url($a->getAttribute('href'));
        if ($url === '') continue;
        $host = strtolower(parse_url($url, PHP_URL_HOST) ?? '');
        if ($host === '' || strpos($host, 'duckduckgo.com') !== false) continue; // skip ads / redirectors
        $title = trim(preg_replace('/\s+/u', ' ', $a->textContent) ?? '');
        $snippet = '';
        // the snippet row, when present, is the very next <tr> after the link's
        $sn = $xp->query('ancestor::tr[1]/following-sibling::tr[1]'
            . '/td[contains(concat(" ", normalize-space(@class), " "), " result-snippet ")]', $a);
        if ($sn->length) $snippet = trim(preg_replace('/\s+/u', ' ', $sn->item(0)->textContent) ?? '');
        $out[] = ['title' => $title !== '' ? $title : $url, 'url' => $url, 'snippet' => $snippet];
        if (count($out) >= 30) break;
    }
    return $out;
}

// Lite canary, the counterpart of df_ddg_page_kind(). Only call it when
// parse_ddg_lite() found zero results.
//   'blocked' -- non-200, or anomaly-modal challenge markup. NOTE: no real lite
//                challenge page has been captured yet; this assumes lite blocks
//                the way the html endpoint does (202 / anomaly-modal). Any other
//                block page still lands in 'markup', never in "No results".
//   'ok'      -- DDG's own no-results box plus the lite search form, as on a
//                real lite zero-results page (tests/fixtures/ddg-lite-zero.html)
//   'markup'  -- anything else
function df_ddg_lite_page_kind(string $html, int $status): string {
    if ($status !== 200 || stripos($html, 'anomaly-modal') !== false) return 'blocked';
    $noResults = preg_match('/class=["\']no-results(__container)?["\']/i', $html) === 1;
    $form = preg_match('#<form[^>]*action=["\']/lite/["\']#i', $html) === 1;
    return ($noResults && $form) ? 'ok' : 'markup';
}

// Fetch an archived snapshot (web.archive.org "id_" raw bytes), trying HTTPS then
// HTTP. The Internet Archive rate-limits per-endpoint under load, so if one port
// is throttled the other usually still answers. Cached by (timestamp, url) so a
// hit skips the network entirely regardless of which scheme succeeded.
// $timeout > 0 is one wall-clock budget across BOTH scheme attempts (the inline
// ASCII path's page budget); 0 keeps the normal per-attempt timeout.
function df_wayback_get(string $ts, string $url, int $ttl = 86400, int $maxlen = 3000000, int $timeout = 0): ?array {
    $key = 'wb:' . $ts . ':' . $url;
    if (($c = df_cache_get($key, $ttl)) !== null) {
        $d = @unserialize($c, ['allowed_classes' => false]);
        if (is_array($d) && !df_cached_stub($d, $maxlen)) return $d;
    }
    $deadline = microtime(true) + $timeout;
    foreach (['https', 'http'] as $scheme) {
        $t = 0;
        if ($timeout > 0) {
            $t = (int)floor($deadline - microtime(true));
            if ($t < 1) break;
        }
        $r = http_get($scheme . '://web.archive.org/web/' . $ts . 'id_/' . $url, $maxlen, '', null, $t);
        // only a real, non-empty 2xx snapshot is worth caching (the same rule
        // as http_get_cached); a throttled 429/5xx must not blank the page for
        // a week, and neither may an empty body. A 4xx/5xx tries the other scheme.
        if ($r !== null && ($r['status'] ?? 200) < 400) {
            if (df_cacheable_response($r) && !df_body_capped($r, $maxlen)) df_cache_put($key, serialize($r));
            return $r;
        }
    }
    return null;
}

// --- Wayback capture years for the reader's era switcher (added 2026-11-08) --
// The switcher lists only years in which the Wayback Machine holds a 200
// capture of the exact URL being read, from the CDX API:
//   /cdx/search/cdx?url=<url>&output=json&fl=timestamp
//                  &collapse=timestamp:4&filter=statuscode:200&limit=100
// collapse=timestamp:4 keeps the first capture of each year, so one row per
// year; checked against real responses 2026-11-08 (apple.com/ -> 31 rows
// 1996-2026 under limit=60, so limit counts collapsed rows; a URL with no
// captures -> "[]"). Those queries took 2.4-17.6 s, far too slow to block a
// render on, so:
//   - read.php only ever reads the cache (df_wayback_years_cached) while it
//     renders; a miss shows the old fixed years;
//   - after the page is sent (fastcgi_finish_request) it calls
//     df_wayback_years_fill() to warm the cache for the next view.
// Keyed per URL, not per domain: captures are per URL, a domain-wide
// "url=host/*" query walks every capture of the whole site (millions for a big
// one), and a year that only has OTHER pages of the domain would just land on
// a redirect to a different year. TTL one day, as asked.
// The cache holds capture years and timestamps only, no visitor data; the key
// derives from the URL being read, exactly like the reader's page cache.
const DF_WBYEARS_TTL     = 86400;   // positive (and "no captures") answers
const DF_WBYEARS_FAILTTL = 3600;    // timeout / bad answer: don't retry for an hour
const DF_WBYEARS_BACKOFF = 900;     // IA said 429/503: no CDX queries at all for 15 min

// The CDX query key: scheme and fragment dropped (CDX canonicalises the scheme
// away itself, and http/https readers of one page should share an entry).
function df_wayback_years_key(string $url): string {
    $u = preg_replace('#^https?://#i', '', $url);
    $h = strpos($u, '#');
    return $h === false ? $u : substr($u, 0, $h);
}

// Parse a CDX output=json&fl=timestamp body into [year => first 14-digit
// timestamp of that year], oldest first. Returns [] for a valid "no captures"
// answer and null for anything that isn't a CDX JSON table (HTML error page,
// truncated body), so the caller can tell "none" from "unknown".
function df_wayback_years_parse(string $body): ?array {
    $j = json_decode($body, true);
    if (!is_array($j)) return null;
    $out = [];
    foreach ($j as $i => $row) {
        if (!is_array($row) || !isset($row[0]) || !is_string($row[0])) return null;
        if ($i === 0 && $row[0] === 'timestamp') continue;     // header row
        if (!preg_match('/^(\d{4})\d{0,10}$/', $row[0], $m)) return null;
        $yr = $m[1];
        if ((int)$yr < 1991 || isset($out[$yr])) continue;     // pre-web junk / dupes
        $out[$yr] = substr(str_pad($row[0], 14, '0'), 0, 14);
    }
    ksort($out, SORT_STRING);
    return $out;
}

// Thin the era switcher to at most $max links so it doesn't wrap at 640/800 px
// wide: $max evenly spaced picks (first and last year always included); if
// $cur (the era being read) isn't among them it replaces the nearest interior
// pick. Order and values are preserved.
function df_wayback_thin(array $links, string $cur = '', int $max = 12): array {
    $keys = array_map('strval', array_keys($links));
    $n = count($keys);
    if ($n <= $max || $max < 3) return $links;
    $pick = [];
    for ($i = 0; $i < $max; $i++) $pick[(int)round($i * ($n - 1) / ($max - 1))] = true;
    $ci = array_search($cur, $keys, true);
    if ($ci !== false && !isset($pick[$ci])) {
        $near = -1;
        foreach ($pick as $k => $_) {
            if ($k === 0 || $k === $n - 1) continue;
            if ($near < 0 || abs($k - $ci) < abs($near - $ci)) $near = $k;
        }
        unset($pick[$near]);
        $pick[$ci] = true;
    }
    $out = [];
    for ($i = 0; $i < $n; $i++) if (isset($pick[$i])) $out[$keys[$i]] = $links[$keys[$i]];
    return $out;
}

// Cache-only lookup: [year => ts] (possibly empty), or null when unknown.
// Never touches the network -- safe to call while rendering.
function df_wayback_years_cached(string $url): ?array {
    $c = df_cache_get('wbyrs:' . df_wayback_years_key($url), DF_WBYEARS_TTL);
    if ($c === null) return null;
    $d = json_decode($c, true);
    return is_array($d) ? array_map('strval', $d) : null;
}

// Query CDX and cache the answer. Meant to run AFTER the response has been
// sent; bounded so it can't pin the php-fpm pool or hammer the Archive:
// one fill site-wide at a time (a flock()ed slot, as in df_slot_try), a short
// negative entry per URL on failure, and a site-wide backoff when IA throttles.
function df_wayback_years_fill(string $url, int $timeout = 20): void {
    $k = df_wayback_years_key($url);
    if ($k === '' || df_wayback_years_cached($url) !== null) return;
    if (df_cache_get('wbyrsfail:' . $k, DF_WBYEARS_FAILTTL) !== null) return;
    if (df_cache_get('wbyrs-backoff', DF_WBYEARS_BACKOFF) !== null) return;
    $slot = df_slot_try(df_rate_dir() . '/.wbyrs_', 1);
    if ($slot === null) return;                       // another fill is running
    try {
        $r = http_get('https://web.archive.org/cdx/search/cdx?url=' . urlencode($k)
            . '&output=json&fl=timestamp&collapse=timestamp:4&filter=statuscode:200&limit=100',
            200000, '', null, $timeout);
        $st = $r === null ? 0 : (int)($r['status'] ?? 0);
        if ($st === 429 || $st === 503) { df_cache_put('wbyrs-backoff', '1'); return; }
        $years = ($st >= 200 && $st < 300) ? df_wayback_years_parse((string)$r['body']) : null;
        if ($years === null) { df_cache_put('wbyrsfail:' . $k, '1'); return; }
        df_cache_put('wbyrs:' . $k, json_encode($years));
    } finally {
        if (is_resource($slot)) { flock($slot, LOCK_UN); fclose($slot); }
    }
}

// Detect a page's charset (header > meta) and convert to UTF-8 so non-UTF-8
// pages (Shift-JIS, ISO-8859-2, windows-1251...) don't come out mangled.
function df_to_utf8(string $html, string $ctype = ''): string {
    $cs = '';
    if ($ctype !== '' && preg_match('/charset=["\']?([\w\-]+)/i', $ctype, $m)) $cs = $m[1];
    if ($cs === '' && preg_match('/<meta[^>]+charset=["\']?([\w\-]+)/i', $html, $m)) $cs = $m[1];
    if ($cs === '' && preg_match('/charset=["\']?([\w\-]+)/i', substr($html, 0, 2048), $m)) $cs = $m[1];
    $cs = strtoupper(trim($cs) ?: 'UTF-8');
    if (in_array($cs, ['UTF-8', 'UTF8', 'US-ASCII', 'ASCII'], true)) return $html;
    if (!in_array($cs, array_map('strtoupper', mb_list_encodings()), true)
        && !preg_match('/^(WINDOWS|ISO|SHIFT|EUC|GB|BIG5|KOI8)/', $cs)) return $html;
    // The prefix regex above admits labels mbstring doesn't know (a real one
    // like windows-874, or a typo like iso-8859-l). On PHP 8 an unknown
    // encoding is a ValueError, not a false return -- @ can't silence it, so
    // one such page was an uncaught fatal (blank 500) in the reader.
    try {
        $conv = @mb_convert_encoding($html, 'UTF-8', $cs);
    } catch (\ValueError $e) {
        return $html;
    }
    return ($conv !== false && $conv !== '') ? $conv : $html;
}

// ===========================================================================
// Abuse controls: keep DuckFind from being turned into a fetch cannon or
// getting our DuckDuckGo scraping blocked.
// ===========================================================================

// The client's IP, used only to key rate limits. Forwarded headers
// (CF-Connecting-IP / X-Forwarded-For) are SPOOFABLE, so we trust them ONLY when
// the direct peer is a configured trusted proxy; otherwise a client could send a
// random header per request and get a fresh rate-limit bucket every time.
function df_client_ip(): string {
    $remote = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    if (df_is_trusted_proxy($remote)) {
        // CF-Connecting-IP is a single address that Cloudflare overwrites.
        $cf = trim((string)($_SERVER['HTTP_CF_CONNECTING_IP'] ?? ''));
        if ($cf !== '' && filter_var($cf, FILTER_VALIDATE_IP)) return $cf;
        // X-Forwarded-For is a chain that each proxy APPENDS to (nginx's
        // $proxy_add_x_forwarded_for, Cloudflare, most load balancers), so its
        // LEFTMOST entry is whatever the client sent -- reading [0] let any
        // client pick a fresh rate-limit bucket per request. Walk it from the
        // right instead, skipping our own trusted hops: the first address a
        // trusted proxy reports that is not itself a trusted proxy is the client.
        $chain = array_map('trim', explode(',', (string)($_SERVER['HTTP_X_FORWARDED_FOR'] ?? '')));
        for ($i = count($chain) - 1; $i >= 0; $i--) {
            $ip = $chain[$i];
            if (!filter_var($ip, FILTER_VALIDATE_IP)) break;   // garbage: trust nothing left of it
            if (!df_is_trusted_proxy($ip) || $i === 0) return $ip;
        }
    }
    return filter_var($remote, FILTER_VALIDATE_IP) ? $remote : '0.0.0.0';
}

function df_is_trusted_proxy(string $ip): bool {
    foreach (df_cfg('trusted_proxies', []) as $cidr) {
        $cidr = (string)$cidr;
        // a bare address means exactly that host: /128 for IPv6, /32 for IPv4
        // (a bare IPv6 entry used to become a /32 -- trusting a whole ISP-sized block)
        if (strpos($cidr, '/') === false) $cidr .= strpos($cidr, ':') !== false ? '/128' : '/32';
        if (df_ip_in_cidr($ip, $cidr)) return true;
    }
    return false;
}

// Directory for rate-limit + daily-counter state. Defaults to a subdir of the
// (disk-backed) cache dir rather than /tmp: on many hosts /tmp is a small tmpfs
// that shares the box's RAM, and if it fills, the file-locked rate limiter fails
// OPEN — silently disabling every per-IP limit and the daily caps. Keeping this
// on the same monitored disk volume as the cache removes that failure mode.
function df_rate_dir(): string {
    // A subdir of the cache dir: it inherits cache_dir's disk volume (off tmpfs)
    // AND its www-data ownership, so it self-provisions with no deploy step. The
    // cache GC's size sweep only globs the hex shard dirs, so it never touches
    // this one; df_rl_gc() below is what expires stale rate files here.
    $d = (string)df_cfg('rate_dir',
        rtrim((string)df_cfg('cache_dir', sys_get_temp_dir() . '/duckfind-cache'), '/') . '/rl');
    if (!is_dir($d)) @mkdir($d, 0700, true);
    return $d;
}

// Per-install random salt for the rate-limit filenames. A bare hash of an IP
// can be reversed by hashing candidate addresses, so salt it; the salt lives
// beside the data it protects (dotfile, so the GC glob skips it) and losing
// it merely resets the buckets.
function df_rl_salt(string $dir): string {
    static $salt = null;
    if ($salt !== null) return $salt;
    $f = $dir . '/.salt';
    $s = @file_get_contents($f);
    if (!is_string($s) || strlen($s) < 32) {
        try { $s = bin2hex(random_bytes(16)); }
        catch (\Throwable $e) { $s = md5(uniqid((string)mt_rand(), true)); }
        @file_put_contents($f, $s, LOCK_EX);
        @chmod($f, 0600);
    }
    return $salt = $s;
}

// --- Browser-proof gate (added 2026-10-06) ----------------------------------
// A distributed bot (thousands of distinct IPs, each well under any sane
// per-IP rate limit) was triggering real.php's outbound fetch directly,
// saturating the small php-fpm pool. Per-IP limits can't stop that -- there's
// no finite IP list. This stops it by BEHAVIOUR instead of identity: any real
// browser, including decades-old ones, follows a redirect and sends back a
// cookie (both plain HTTP/1.0+ features, no JS needed); a script hitting the
// URL directly does neither. Guard only the expensive code path in a script
// (after its cheap/static branches already returned) -- never the whole site.
function df_pob_secret(): string {
    static $secret = null;
    if ($secret !== null) return $secret;
    $dir = df_rate_dir();
    $f = $dir . '/.pobsecret';
    $s = @file_get_contents($f);
    if (!is_string($s) || strlen($s) < 32) {
        try { $s = bin2hex(random_bytes(32)); }
        catch (\Throwable $e) { $s = hash('sha256', uniqid((string)mt_rand(), true)); }
        @file_put_contents($f, $s, LOCK_EX);
        @chmod($f, 0600);
    }
    return $secret = $s;
}

function df_pob_token(): string {
    $ts = (string)time();
    return $ts . '.' . hash_hmac('sha256', $ts, df_pob_secret());
}

function df_pob_valid(string $token, int $maxAge = 3600): bool {
    $parts = explode('.', $token, 2);
    if (count($parts) !== 2) return false;
    [$ts, $sig] = $parts;
    if (!ctype_digit($ts)) return false;
    $age = time() - (int)$ts;
    if ($age > $maxAge || $age < -60) return false;   // expired, or absurd clock skew
    return hash_equals(hash_hmac('sha256', $ts, df_pob_secret()), $sig);
}

// Call at the top of an expensive branch. First hit: sets the cookie and
// redirects back to the exact same request (query string preserved) -- a
// real browser completes this transparently in one extra round trip. Second
// hit still missing a valid cookie (marked by _pob=1, so we never redirect
// twice): a plain explanation instead of a redirect loop, so a real visitor
// with cookies disabled doesn't get stuck bouncing forever -- they just can't
// use this one feature until cookies are on, same as any cookie-gated site.
// Vintage/minimal browsers (df_pob_is_legacy: MacWeb, Mosaic, Lynx, iCab,
// Netscape 0.9-4 ...) pass without the cookie: many can't keep one at all and
// they are this site's core audience. Each such pass bumps one aggregate daily
// counter (daily_pobxlegacy), nothing per client. Known crawlers are NOT
// exempted here even if their UA looks old (df_pob_classify checks bots first):
// they stay out of the expensive paths, as before. $allowLegacy = false keeps
// the strict cookie rule for a PAID path (ask.php): a User-Agent is trivially
// faked, and there a script could drain the site-wide ai_daily_cap.
// This request's own path and query string without the gate's _pob marker
// (relative, same script): where the visitor really wanted to go.
function df_pob_clean_url(): string {
    $self = (string)($_SERVER['SCRIPT_NAME'] ?? '/');
    if (substr($self, -10) === '/index.php') $self = substr($self, 0, -9);   // "/" stays "/"
    $qs = (string)($_SERVER['QUERY_STRING'] ?? '');
    $parts = array_filter(explode('&', $qs), function ($p) {
        return $p !== '' && $p !== '_pob=1' && strpos($p, '_pob=') !== 0;
    });
    return $self . ($parts ? '?' . implode('&', $parts) : '');
}
function df_pob_set_cookie(): void {
    setcookie('df_pob', df_pob_token(), [
        'expires' => time() + 3600, 'path' => '/', 'samesite' => 'Lax', 'httponly' => true,
    ]);
}
function df_require_browser_proof(bool $allowLegacy = true): void {
    $marked = ($_GET['_pob'] ?? '') === '1';
    if ($allowLegacy ? df_pob_pass() : df_pob_valid(df_str($_COOKIE['df_pob'] ?? ''))) {
        // Passed on the marked URL: send the browser on to the clean one, so
        // the _pob=1 copy never ends up in a bookmark, a restored tab or a
        // shared link (2026-11-12) -- see the dead end below.
        if ($marked && ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET' && !headers_sent()) {
            header('Location: ' . df_pob_clean_url(), true, 302);
            exit;
        }
        return;
    }

    if ($marked) {
        // Either cookies are off, or this is an old _pob=1 URL (bookmark, restored
        // tab, shared link) whose one-hour cookie expired. This page used to set
        // nothing, so the second case was a permanent dead end (2026-11-12):
        // set a fresh cookie and offer the clean URL -- with cookies on, the
        // link just works; with them off, the visitor lands back here.
        df_pob_set_cookie();
        header('Content-Type: text/html; charset=iso-8859-1');
        echo page_head(DUCKFIND_NAME . ' - cookies required', true)
           . '<h1>Cookies are required for this feature</h1>'
           . '<p>This page needs a short-lived cookie to confirm a real browser is '
           . 'asking, not an automated script.</p>'
           . '<p><a href="' . htmlspecialchars(df_pob_clean_url(), ENT_QUOTES) . '">Continue</a>'
           . ' -- if you come straight back here, please enable cookies and try again.</p>'
           . page_foot();
        exit;
    }

    df_pob_set_cookie();
    $qs = (string)($_SERVER['QUERY_STRING'] ?? '');
    $self = (string)$_SERVER['SCRIPT_NAME'];
    if (substr($self, -10) === '/index.php') $self = substr($self, 0, -9);   // "/" stays "/"
    header('Location: ' . $self . '?' . ($qs !== '' ? $qs . '&' : '') . '_pob=1', true, 302);
    exit;
}

// Occasionally sweep rate-limit files whose window has long passed, so
// hashed-IP entries don't sit on disk indefinitely. Daily counters get 48h
// (they must survive their whole UTC day even if traffic pauses). Runs on
// ~0.5% of rate checks, same scheme as df_cache_gc().
function df_rl_gc(string $dir): void {
    if (function_exists('random_int')) { try { if (random_int(1, 200) !== 1) return; } catch (\Throwable $e) { return; } }
    elseif (mt_rand(1, 200) !== 1) return;
    $maxwin = 3600;
    foreach (df_cfg('rate', []) as $r) {
        if (is_array($r) && isset($r[1])) $maxwin = max($maxwin, (int)$r[1]);
    }
    $now = time();
    foreach (glob($dir . '/*') ?: [] as $f) {
        $cut = (strpos(basename($f), 'daily_') === 0) ? 2 * 86400 : 2 * $maxwin;
        if (@filemtime($f) < $now - $cut) @unlink($f);
    }
}

// Sliding-window per-IP rate limit backed by a temp file. True if allowed.
// Holds an exclusive lock across the whole read-modify-write so concurrent
// requests can't race past the limit (fails open on FS error to protect uptime).
// $consume=false only asks whether the bucket still has room, recording nothing
// (used to charge failures only, e.g. wrong feed codes).
function df_rate_ok(string $bucket, int $limit, int $window, bool $consume = true): bool {
    if (PHP_SAPI === 'cli') return true;
    $dir = df_rate_dir();
    $f = $dir . '/' . $bucket . '_' . sha1(df_rl_salt($dir) . df_client_ip());
    $fp = @fopen($f, 'c+');
    if ($fp === false) return true;
    if (!flock($fp, LOCK_EX)) { fclose($fp); return true; }
    $now = time();
    $hits = [];
    foreach (explode(',', (string)stream_get_contents($fp)) as $ts) {
        if ($ts !== '' && (int)$ts > $now - $window) $hits[] = (int)$ts;
    }
    $ok = count($hits) < $limit;
    if ($ok && $consume) {
        $hits[] = $now;
        ftruncate($fp, 0); rewind($fp);
        fwrite($fp, implode(',', $hits));
    }
    fflush($fp); flock($fp, LOCK_UN); fclose($fp);
    df_rl_gc($dir);
    return $ok;
}

// --- Browser-proof gate on cheap pages (measurement 2026-11-07, gate 2026-11-08)
// Every 'page'-bucket hit bumps exactly one of four aggregate daily counters
// (daily_pobyes / pobno / pobbot / poblegacy in the rate dir), then:
//   yes    -- valid df_pob cookie: passes.
//   bot    -- known search crawler (never keeps cookies): passes, never gated.
//   legacy -- vintage/minimal browser, many of which (MacWeb, Mosaic, early
//             Netscape, text-mode stacks) have no cookie support at all and are
//             this site's core audience: passes, gets a cookie it may ignore.
//   no     -- everything else (modern UA, empty UA, scripts): one 302 that sets
//             the cookie, then the cookies-required page if it still has none
//             (df_require_browser_proof). Measurement showed ~99.5% of 'no'
//             traffic never returns the cookie: that's the scraper this stops.
// Only GET/HEAD are gated (a 302 would drop a POST body, e.g. a guestbook entry
// typed past the cookie's 1h expiry). Scripts that must never get the HTML
// cookies page (XML docs, the map click redirect) define DF_POB_EXEMPT before
// calling df_rate('page'): still counted, never gated. 'pob_gate' => false in
// config.php turns the gate off without a deploy (counting continues).
// Privacy: four integers per UTC day, nothing per client; the User-Agent is
// only pattern-matched in memory, never stored. (The expensive-path gate,
// df_require_browser_proof, adds a fifth: daily_pobxlegacy, its legacy passes.)
const DF_POB_BOT_RE = '/googlebot|bingbot|duckduckbot|applebot|yandex(bot|images)|baiduspider|slurp|kagibot|mojeekbot|qwantify|seznambot|petalbot/i';
// Named vintage/minimal browsers: matched as product tokens, and they win even
// if the UA also carries a modern token (WebPositive and Classilla do).
const DF_POB_LEGACY_NAMED_RE = '~\b(MacWeb|MacMosaic|NCSA[ _]Mosaic|Mosaic/|iCab|Lynx/|Links \(|ELinks/|w3m/|Dillo/|NetSurf/|Classilla|WebPositive/|Cyberdog|AWeb|IBrowse|Voyager/|OmniWeb/[0-4]\.|Opera[/ ][2-6]\.)|Arachne/~i';
// Generic old Mozilla: Mozilla/0.x-4.x (Netscape 0.9-4, MSIE 2-5 "compatible")
// with no token that only modern or post-2001 browsers send.
const DF_POB_LEGACY_MOZ_RE = '~^Mozilla/[0-4]\.~';
const DF_POB_MODERN_RE = '~Chrome/|Chromium/|Firefox/|Safari/|Edg[eA]?/|OPR/|Trident/|Gecko/|MSIE ([6-9]|1\d)\.~';

function df_pob_is_legacy(string $ua): bool {
    if ($ua === '') return false;
    if (preg_match(DF_POB_LEGACY_NAMED_RE, $ua)) return true;
    return preg_match(DF_POB_LEGACY_MOZ_RE, $ua) === 1 && preg_match(DF_POB_MODERN_RE, $ua) !== 1;
}

function df_pob_classify(string $cookie, string $ua): string {
    if (df_pob_valid($cookie)) return 'yes';
    if ($ua !== '' && preg_match(DF_POB_BOT_RE, $ua)) return 'bot';
    if (df_pob_is_legacy($ua)) return 'legacy';
    return 'no';
}

// df_require_browser_proof()'s cookie check, with the vintage-browser exemption:
// true for a valid df_pob cookie, or for a cookieless legacy (non-bot) UA, which
// is counted in daily_pobxlegacy. Also used where a gate can't redirect
// (df_ascii_inline), so both apply the same rule.
function df_pob_pass(): bool {
    $k = df_pob_classify(df_str($_COOKIE['df_pob'] ?? ''), df_str($_SERVER['HTTP_USER_AGENT'] ?? ''));
    if ($k === 'yes') return true;
    if ($k !== 'legacy') return false;
    df_daily_inc('pobxlegacy');
    return true;
}

function df_pob_measure(): void {
    $k = df_pob_classify(df_str($_COOKIE['df_pob'] ?? ''), df_str($_SERVER['HTTP_USER_AGENT'] ?? ''));
    df_daily_inc('pob' . $k);
    if ($k === 'yes' || $k === 'bot' || headers_sent()) return;
    $method = strtoupper(df_str($_SERVER['REQUEST_METHOD'] ?? 'GET'));
    if ($k === 'no' && df_cfg('pob_gate', true) && !defined('DF_POB_EXEMPT')
        && ($method === 'GET' || $method === 'HEAD')) {
        df_require_browser_proof();   // 302 + Set-Cookie, or the cookies page; exits
    }
    setcookie('df_pob', df_pob_token(), [
        'expires' => time() + 3600, 'path' => '/', 'samesite' => 'Lax', 'httponly' => true,
    ]);
}

// Convenience: apply the configured [limit, window] for a named bucket.
function df_rate(string $bucket): bool {
    if ($bucket === 'page' && PHP_SAPI !== 'cli') df_pob_measure();
    $r = (df_cfg('rate', [])[$bucket] ?? null);
    return is_array($r) ? df_rate_ok($bucket, (int)$r[0], (int)$r[1]) : df_rate_ok($bucket, 60, 60);
}

function df_rate_block(): void {
    http_response_code(429);
    header('Content-Type: text/html; charset=iso-8859-1');
    header('Retry-After: 30');
    echo page_head('Slow down') . '<h1>Too many requests</h1>'
       . '<p>DuckFind is rate-limited so it stays available for everyone. '
       . 'Please wait a few seconds and try again. The <a href="/about.php">about page</a> '
       . 'lists the limits.</p>' . page_foot();
    exit;
}

// Site-wide daily counter — the hard cost ceiling for paid features (AI answers).
// Unlike df_rate (per-IP), this caps TOTAL daily usage so the bill can't run away
// no matter how many different IPs call in. The file name carries the UTC date,
// so the count resets each day and stale files are harmless.
function df_daily_file(string $bucket): string {
    return df_rate_dir() . '/daily_' . preg_replace('/[^a-z0-9]/i', '', $bucket) . '_' . gmdate('Ymd');
}
function df_daily_count(string $bucket): int {
    $c = @file_get_contents(df_daily_file($bucket));
    return $c === false ? 0 : (int)$c;
}
// Adjust the counter by $delta (default +1). Pass -1 to refund a reserved slot
// whose paid action failed. The counter never goes below zero.
function df_daily_inc(string $bucket, int $delta = 1): void {
    $fp = @fopen(df_daily_file($bucket), 'c+');
    if ($fp === false) return;
    if (flock($fp, LOCK_EX)) {
        $n = (int)stream_get_contents($fp);
        ftruncate($fp, 0); rewind($fp); fwrite($fp, (string)max(0, $n + $delta));
        fflush($fp); flock($fp, LOCK_UN);
    }
    fclose($fp);
}
// Reserve one unit of a capped daily counter: the cap check and the increment
// happen under the same lock, so a concurrent burst can't all read count < cap
// before any of them increments (each caller either gets a slot or doesn't).
// Returns false, without incrementing, when the counter is already at $cap.
// $cap <= 0 means uncapped: always counts and returns true. If the counter file
// can't be opened or locked this fails open, matching df_daily_count()'s 0.
function df_daily_inc_capped(string $bucket, int $cap): bool {
    return df_counter_inc_capped(df_daily_file($bucket), $cap);
}
// The shared atomic check+reserve behind df_daily_inc_capped() and
// df_hourly_inc_capped(); $file is the counter file for the current period.
function df_counter_inc_capped(string $file, int $cap): bool {
    $fp = @fopen($file, 'c+');
    if ($fp === false) return true;
    $ok = true;
    if (flock($fp, LOCK_EX)) {
        $n = (int)stream_get_contents($fp);
        if ($cap > 0 && $n >= $cap) {
            $ok = false;
        } else {
            ftruncate($fp, 0); rewind($fp); fwrite($fp, (string)max(0, $n + 1));
            fflush($fp);
        }
        flock($fp, LOCK_UN);
    }
    fclose($fp);
    return $ok;
}

// Site-wide HOURLY counter (added 2026-11-08) -- same semantics as the daily
// one above (atomic check+reserve under flock, fails open on a file error),
// keyed to the UTC hour. Used where a daily budget would let a burst burn the
// whole day in minutes: ftp.php's outbound fetches. The name carries the hour
// ("hourly_<bucket>_YYYYMMDDHH"), so the count resets on the hour and old
// files are dead weight that df_rl_gc() expires like any rate file (their
// last write is always inside their own hour, and the GC cut is >= 2h).
// $now is for tests only.
function df_hourly_file(string $bucket, ?int $now = null): string {
    return df_rate_dir() . '/hourly_' . preg_replace('/[^a-z0-9]/i', '', $bucket) . '_'
         . gmdate('YmdH', $now ?? time());
}
function df_hourly_count(string $bucket, ?int $now = null): int {
    $c = @file_get_contents(df_hourly_file($bucket, $now));
    return $c === false ? 0 : (int)$c;
}
function df_hourly_inc_capped(string $bucket, int $cap, ?int $now = null): bool {
    return df_counter_inc_capped(df_hourly_file($bucket, $now), $cap);
}
// Seconds until the next UTC hour starts (1..3600): the Retry-After for an
// hourly cap.
function df_secs_to_next_hour(?int $now = null): int {
    return 3600 - (($now ?? time()) % 3600);
}

// --- FTP gateway: site-wide hourly fetch budget (added 2026-11-08) ----------
// Per-client limits and the browser-proof cookie don't stop a cookie-capable
// bot spread over hundreds of addresses, and every ftp.php listing or file is
// a real outbound FTP session from this server. This caps the TOTAL number of
// those per UTC hour, whoever asks. 'ftp_hourly_cap' in config; 0 = off.
// Reserve one unit right before a fetch; false means the hour's budget is
// spent (and bumps the aggregate daily 'ftpcapped' counter -- an integer per
// day, nothing per client). Fails open on a filesystem error.
function df_ftp_budget_ok(?int $now = null): bool {
    if (df_hourly_inc_capped('ftp', (int)df_cfg('ftp_hourly_cap', 200), $now)) return true;
    if (df_captcha_pass('ftp', (int)df_cfg('ftp_hourly_cap', 200), $now)) return true;   // solved captcha
    df_daily_inc('ftpcapped');
    return false;
}
// --- Map: site-wide hourly OSM tile budget (added 2026-11-12) -----------------
// map.php's GIF mode stitches tiles from tile.openstreetmap.org; every tile not
// already in our 7-day cache is one outbound fetch under MAP_UA. A distributed
// swarm (2026-11-11: ~12k clients, ~1 map GIF each, passing the cookie gate)
// can drive ~1k uncached tile fetches an hour, which OSM's tile usage policy
// does not allow. This caps the TOTAL uncached tile fetches per UTC hour,
// whoever asks: over it, map.php uses cached tiles only and leaves the rest
// grey (the map is still served, uncached, so it fills in after the hour).
// 'map_tile_hourly_cap' in config; 0 = off. Reserve one unit right before each
// fetch. Fails open on a filesystem error, like df_ftp_budget_ok().
function df_map_tile_budget_ok(?int $now = null): bool {
    if (df_hourly_inc_capped('maptile', (int)df_cfg('map_tile_hourly_cap', 300), $now)) return true;
    return df_captcha_pass('maptile', (int)df_cfg('map_tile_hourly_cap', 300), $now);   // solved captcha
}
// Whether this hour's tile budget is spent (map.php's HTML page then asks for
// the captcha before showing a map that would come back grey). Reserves nothing.
function df_map_tiles_spent(?int $now = null): bool {
    $cap = (int)df_cfg('map_tile_hourly_cap', 300);
    return $cap > 0 && df_hourly_count('maptile', $now) >= $cap;
}
// --- Reader: site-wide hourly fetch budget (added 2026-11-12) ----------------
// read.php fetches the page being read (live, or a Wayback snapshot) on a
// cache miss. Per-client limits and the cookie gate don't stop a swarm spread
// over thousands of addresses (2026-11-11: reads went from ~2 to 1,358 an
// hour). This caps the TOTAL number of uncached reads per UTC hour, whoever
// asks; pages already in the cache keep working. One unit covers one read,
// including its follow-up Wayback availability lookup on a failed or blocked
// page. ascii-mode image fetches are not counted here (they have their own
// per-page count, time budget and df_rate('img')). 'read_hourly_cap' in
// config; 0 = off. False means the hour's budget is spent and bumps the
// aggregate daily 'readcapped' counter (an integer per day, nothing per
// client). Fails open on a filesystem error.
function df_read_budget_ok(?int $now = null): bool {
    if (df_hourly_inc_capped('read', (int)df_cfg('read_hourly_cap', 300), $now)) return true;
    if (df_captcha_pass('read', (int)df_cfg('read_hourly_cap', 300), $now)) return true;   // solved captcha
    df_daily_inc('readcapped');
    return false;
}
// --- Reader: signed result links (added 2026-11-12) -------------------------
// A swarm hammering read.php directly with arbitrary URLs filled the hourly
// 'read' budget every hour, so real readers got the captcha too. Links that
// DuckFind itself renders to /read.php (search results, news, Hacker News,
// feeds) carry t = HMAC(df_pob_secret, 'readtok|' . url . '|' . UTC hour),
// valid for the current and previous hour. A valid t lets that one URL skip
// ONLY the hourly 'read' reserve -- per-IP rate limits, the cookie gate, the
// render cap and daily caps all still apply. Nothing about the client is in
// it: it binds the exact URL and the hour, nothing else.
// Harvesting (links on our own news/HN/feed pages can be read without a
// search) is bounded by a site-wide hourly ceiling on token-bypassed uncached
// reads: 'read_token_hourly_mult' x read_hourly_cap (default 3; 0 = off, the
// bypass is never used). Past it, the normal cap path applies (captcha/busy).
// Aggregate daily counter 'readtokbypass'.
const DF_READTOK_LEN = 24;
function df_readtok_at(string $url, int $bucket): string {
    return substr(hash_hmac('sha256', 'readtok|' . $url . '|' . $bucket, df_pob_secret()), 0, DF_READTOK_LEN);
}
function df_readtok(string $url, ?int $now = null): string {
    return df_readtok_at($url, intdiv($now ?? time(), 3600));
}
// "&t=<token>" for a reader link to $url (raw '&'; callers HTML-escape as they
// already do for the rest of the href, or use $html = true for '&amp;').
function df_readtok_qs(string $url, bool $html = false): string {
    return ($html ? '&amp;' : '&') . 't=' . df_readtok($url);
}
// Valid for the current or the previous UTC hour; constant-time compare.
function df_readtok_valid(string $url, string $t, ?int $now = null): bool {
    if (!preg_match('/^[0-9a-f]{' . DF_READTOK_LEN . '}$/', $t)) return false;
    $b = intdiv($now ?? time(), 3600);
    return hash_equals(df_readtok_at($url, $b), $t) || hash_equals(df_readtok_at($url, $b - 1), $t);
}
// A valid token for this URL, and the site-wide token ceiling not reached:
// reserve one unit of it and skip the hourly read reserve. Anything else
// (no/tampered/expired/wrong-URL token, bypass off, ceiling spent) returns
// false WITHOUT side effects, so the caller falls back to df_read_budget_ok().
function df_read_token_bypass_ok(string $url, string $t, ?int $now = null): bool {
    $mult = (int)df_cfg('read_token_hourly_mult', 3);
    $cap  = (int)df_cfg('read_hourly_cap', 300);
    if ($mult <= 0 || $cap <= 0 || $t === '' || !df_readtok_valid($url, $t, $now)) return false;
    if (!df_hourly_inc_capped('readtok', $mult * $cap, $now)) return false;
    df_daily_inc('readtokbypass');
    return true;
}
// Whether read.php's fetch for $url (with Wayback timestamp $ts, '' = live)
// would be served from the cache: the same keys and TTLs read.php passes to
// http_get_cached() and df_wayback_get().
function df_read_cached(string $url, string $ts = ''): bool {
    return $ts !== ''
        ? df_cache_get('wb:' . $ts . ':' . $url, 86400) !== null
        : df_cache_get('raw:' . $url, 1800) !== null;
}
function df_read_budget_block(): void {
    df_captcha_block('read', (int)df_cfg('read_hourly_cap', 300));                                  // returns only when the captcha is off
    http_response_code(503);
    header('Content-Type: text/html; charset=iso-8859-1');
    header('Retry-After: ' . df_secs_to_next_hour());
    echo page_head(DUCKFIND_NAME . ' - reader busy', true) . '<h1>The reader is busy</h1>'
       . '<p>The reader only fetches a limited number of new pages each hour, shared by '
       . 'everyone, and this hour&#39;s are used up. Pages someone read recently still '
       . 'work. Please try again after the top of the hour.</p>'
       . '<p><a href="/">Back to search</a></p>' . page_foot();
    exit;
}

// --- Search: site-wide hourly DDG budget + block backoff (added 2026-11-12) --
// 2026-11-12 DuckDuckGo flagged bespin's IP: the html endpoint answered 202
// "anomaly" to every query and lite followed, so search was down for everyone.
// Two guards so a swarm can't get us flagged again, and so we stop re-hitting
// DDG while we are:
//
// 1. An HOURLY cap on uncached DDG fetches (html and the lite fallback count
//    together, one unit per outbound request), on top of the daily
//    'search_daily_cap': the daily cap alone let a burst spend thousands in an
//    hour. 'search_hourly_cap' in config; 0 = off. False means this hour's
//    budget is spent and bumps the aggregate daily 'searchcapped' counter.
//    Fails open on a filesystem error, like the other budgets.
function df_search_budget_ok(?int $now = null): bool {
    if (df_hourly_inc_capped('search', (int)df_cfg('search_hourly_cap', 200), $now)) return true;
    if (df_captcha_pass('search', (int)df_cfg('search_hourly_cap', 200), $now)) return true;   // solved captcha
    df_daily_inc('searchcapped');
    return false;
}
function df_search_busy_block(): void {
    df_captcha_block('search', (int)df_cfg('search_hourly_cap', 200));                                  // returns only when the captcha is off
    http_response_code(503);
    header('Content-Type: text/html; charset=iso-8859-1');
    header('Retry-After: ' . df_secs_to_next_hour());
    echo page_head(DUCKFIND_NAME . ' - search busy', true) . '<h1>Search is busy</h1>'
       . '<p>' . DUCKFIND_NAME . ' only sends a limited number of new searches to '
       . df_search_engine_name() . ' each hour, shared by everyone, and this hour&#39;s are used up. '
       . 'Recently searched terms still work. Please try again after the top of the hour.</p>'
       . '<p><a href="/">Back to search</a></p>' . page_foot();
    exit;
}

// Reserve one outbound DDG request against the hourly cap, then the daily
// 'search_daily_cap'. '' = reserved; 'hourly' / 'daily' = that cap refused it
// (the hourly refusal is counted in 'searchcapped' by df_search_budget_ok).
function df_search_reserve(): string {
    if (!df_search_budget_ok()) return 'hourly';
    if (!df_daily_inc_capped('search', (int)df_cfg('search_daily_cap', 5000))) return 'daily';
    return '';
}
function df_search_daily_block(): void {
    http_response_code(429);
    header('Content-Type: text/html; charset=iso-8859-1');
    echo page_head('Search limit reached', true)
       . '<h1>Daily search limit reached</h1>'
       . '<p>DuckFind has run as many new searches as it can for today '
       . '(a site-wide cap protects the search backend for everyone; see the '
       . '<a href="/about.php">about page</a>). '
       . 'Recently searched terms still work. Please try again tomorrow.</p>'
       . page_foot();
    exit;
}

// 2. A BACKOFF per DDG endpoint ('html', 'lite', 'translate') after it answers
//    with a block (202 / anomaly-modal): for the backoff period that endpoint
//    is not contacted at all. Per endpoint, not shared: on 2026-11-12 DDG
//    challenged html from every address we have while lite still answered
//    from some, so html backing off must not stop lite being tried. The
//    period steps 60 s -> 5 min -> 15 min while the endpoint keeps blocking
//    (a new block within DF_DDG_BACKOFF_RESET seconds of the last period
//    ending escalates; later than that starts over at 60 s), and a readable
//    answer from it clears it. State is one small file per endpoint in the
//    rate dir: {"until": unix, "level": 1..3} -- nothing about the query or
//    the client. Fails open on a file error.
const DF_DDG_BACKOFF_STEPS = [60, 300, 900];
const DF_DDG_BACKOFF_RESET = 900;
function df_ddg_backoff_file(string $ep): string {
    return df_rate_dir() . '/ddg_backoff_' . preg_replace('/[^a-z]/', '', $ep);
}
function df_ddg_backoff_state(string $ep): array {
    $c = @file_get_contents(df_ddg_backoff_file($ep));
    $d = $c === false ? null : json_decode($c, true);
    return is_array($d) ? ['until' => (int)($d['until'] ?? 0), 'level' => (int)($d['level'] ?? 0)]
                        : ['until' => 0, 'level' => 0];
}
// Seconds left in $ep's current backoff (0 = none: it may be contacted).
function df_ddg_backoff_remaining(string $ep, ?int $now = null): int {
    return max(0, df_ddg_backoff_state($ep)['until'] - ($now ?? time()));
}
// Record a block from $ep; returns the seconds until it may be contacted
// again. A block reported while its backoff is already running (requests in
// flight when it started) does not escalate it.
function df_ddg_backoff_hit(string $ep, ?int $now = null): int {
    $now = $now ?? time();
    $fp = @fopen(df_ddg_backoff_file($ep), 'c+');
    if ($fp === false) return 0;
    $wait = 0;
    if (flock($fp, LOCK_EX)) {
        $d = json_decode((string)stream_get_contents($fp), true);
        $until = is_array($d) ? (int)($d['until'] ?? 0) : 0;
        $level = is_array($d) ? (int)($d['level'] ?? 0) : 0;
        if ($now < $until) {
            $wait = $until - $now;
        } else {
            $level = ($level > 0 && $now < $until + DF_DDG_BACKOFF_RESET)
                   ? min($level + 1, count(DF_DDG_BACKOFF_STEPS)) : 1;
            $wait = DF_DDG_BACKOFF_STEPS[$level - 1];
            ftruncate($fp, 0); rewind($fp);
            fwrite($fp, json_encode(['until' => $now + $wait, 'level' => $level]));
            fflush($fp);
        }
        flock($fp, LOCK_UN);
    }
    fclose($fp);
    return $wait;
}
// $ep answered readably: drop its backoff state (cheap no-op when there is none).
function df_ddg_backoff_clear(string $ep): void {
    $f = df_ddg_backoff_file($ep);
    if (is_file($f)) @unlink($f);
}
// Whether a DDG response is a block: the statuses DDG throttles with (202 is
// its challenge, 403/429 plain refusals) or the anomaly challenge markup.
// Other errors (a stale-token 4xx, a 5xx) are not blocks and don't back off.
function df_ddg_is_block(?array $r): bool {
    return $r !== null && (in_array((int)($r['status'] ?? 200), [202, 403, 429], true)
                           || stripos((string)($r['body'] ?? ''), 'anomaly-modal') !== false);
}
function df_search_unavailable_block(int $wait): void {
    http_response_code(503);
    header('Content-Type: text/html; charset=iso-8859-1');
    header('Retry-After: ' . max(1, $wait));
    echo page_head(DUCKFIND_NAME . ' - search unavailable', true)
       . '<p><b>Search is temporarily unavailable.</b> ' . df_search_engine_name() . ' is not answering '
       . DUCKFIND_NAME . '&#39;s searches right now. Please try again in a few minutes. '
       . 'Recently searched terms still work.</p>'
       . '<p><a href="/">Back to search</a></p>' . page_foot();
    exit;
}

// --- Over-cap captcha (added 2026-11-12) -------------------------------------
// When a site-wide HOURLY cap refuses (search, reader, FTP, map tiles), a person
// can solve a captcha instead of waiting for the top of the hour. A swarm sends
// ~1 request per address and never solves it. Works in any browser that shows a
// GIF and submits a form (no JS, no CSS, no third party). Text-only browsers
// can't see the image; its alt text tells them to try after the hour.
//
// Stateless and private:
//  - a challenge is "<issued ts>.<random hex>"; its 5-character answer is
//    derived from it with an HMAC under df_pob_secret(), so only we can draw or
//    check it. Challenges expire after DF_CAPTCHA_TTL seconds, and a solved one
//    is recorded (rate dir, flock, 10 min) so it can't be used twice.
//  - solving sets cookie df_cap = "<expiry>.<random id>.<hmac>": signed by us,
//    1 hour, nothing about the client in it. A copied cookie is still only
//    worth its own budget: each token id gets 'captcha_token_budget' (default
//    30) cap-exempt fetches per hour, counted in hourly_captok<id> -- keyed by
//    the token, never by IP. Spent: the captcha again (daily 'capspent').
//  - a token only lifts the HOURLY caps. Per-IP rate limits, the daily caps,
//    the DDG backoff, stream slots and the cookie gate all still apply.
//  - aggregate daily counters only: capshown, capsolved, capfailed, capspent.
// 'captcha_enabled' => false keeps the plain busy pages.
const DF_CAPTCHA_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';   // no 0/O/1/I/L
const DF_CAPTCHA_LEN = 5;
const DF_CAPTCHA_TTL = 600;
const DF_CAPTCHA_TOKEN_TTL = 3600;
function df_captcha_enabled(): bool {
    return (bool)df_cfg('captcha_enabled', true);
}
function df_captcha_new(?int $now = null): string {
    try { $r = bin2hex(random_bytes(8)); }
    catch (\Throwable $e) { $r = substr(hash('sha256', uniqid((string)mt_rand(), true)), 0, 16); }
    return (string)($now ?? time()) . '.' . $r;
}
// A well-formed challenge inside its lifetime ('' and anything else: false).
function df_captcha_challenge_ok(string $c, ?int $now = null): bool {
    if (!preg_match('/^([0-9]{1,12})\.([0-9a-f]{16})$/', $c, $m)) return false;
    $age = ($now ?? time()) - (int)$m[1];
    return $age >= -60 && $age <= DF_CAPTCHA_TTL;
}
function df_captcha_answer(string $c): string {
    $h = hash_hmac('sha256', 'captcha|' . $c, df_pob_secret(), true);
    $n = strlen(DF_CAPTCHA_ALPHABET);
    $out = '';
    for ($i = 0; $i < DF_CAPTCHA_LEN; $i++) $out .= DF_CAPTCHA_ALPHABET[ord($h[$i]) % $n];
    return $out;
}
// Normalise what a person typed: case and spaces.
function df_captcha_norm(string $a): string {
    return strtoupper(preg_replace('/\s+/', '', $a) ?? '');
}
// Check an answer; a correct one is consumed (recorded so it can't be reused).
function df_captcha_check(string $c, string $a, ?int $now = null): bool {
    if (!df_captcha_challenge_ok($c, $now)) return false;
    if (!hash_equals(df_captcha_answer($c), df_captcha_norm($a))) return false;
    return df_captcha_consume($c, $now);
}
// Record a solved challenge; false if it was already used. One small file of
// "<ts> <challenge>" lines in the rate dir, pruned to the last DF_CAPTCHA_TTL.
// Fails open on a file error (the answer was already right).
function df_captcha_consume(string $c, ?int $now = null): bool {
    $now = $now ?? time();
    $fp = @fopen(df_rate_dir() . '/captcha_used', 'c+');
    if ($fp === false) return true;
    $ok = true;
    if (flock($fp, LOCK_EX)) {
        $keep = [];
        foreach (explode("\n", (string)stream_get_contents($fp)) as $ln) {
            $p = explode(' ', $ln, 2);
            if (count($p) !== 2 || (int)$p[0] < $now - DF_CAPTCHA_TTL - 60) continue;
            if ($p[1] === $c) $ok = false;
            $keep[] = $ln;
        }
        if ($ok) $keep[] = $now . ' ' . $c;
        ftruncate($fp, 0); rewind($fp); fwrite($fp, implode("\n", $keep)); fflush($fp);
        flock($fp, LOCK_UN);
    }
    fclose($fp);
    return $ok;
}
function df_captcha_token(?int $now = null): string {
    try { $id = bin2hex(random_bytes(8)); }
    catch (\Throwable $e) { $id = substr(hash('sha256', uniqid((string)mt_rand(), true)), 0, 16); }
    $p = (string)(($now ?? time()) + DF_CAPTCHA_TOKEN_TTL) . '.' . $id;
    return $p . '.' . hash_hmac('sha256', 'captok|' . $p, df_pob_secret());
}
// The token's id if it is ours (HMAC) and unexpired, else null.
function df_captcha_token_id(string $t, ?int $now = null): ?string {
    if (!preg_match('/^([0-9]{1,12})\.([0-9a-f]{16})\.([0-9a-f]{64})$/', $t, $m)) return null;
    $now = $now ?? time();
    if ((int)$m[1] <= $now || (int)$m[1] > $now + DF_CAPTCHA_TOKEN_TTL + 60) return null;
    $want = hash_hmac('sha256', 'captok|' . $m[1] . '.' . $m[2], df_pob_secret());
    return hash_equals($want, $m[3]) ? $m[2] : null;
}
// Over an hourly cap: does this request's df_cap token let it through? A valid
// token with budget left takes one unit of it (true). A valid but spent token
// counts 'capspent' (false: the caller shows the captcha again).
// Hard hourly CEILING on token-funded units, per capped bucket (added
// 2026-11-12, HK-47 review): a GD text captcha is OCR-solvable, so a swarm
// that solves it would get captcha_token_budget units per token with no upper
// bound -- and map tiles and reader fetches have no daily cap behind them.
// Tokens may spend at most (captcha_ceiling_mult - 1) x the bucket's hourly
// cap extra per hour (default mult 2: the cap again); past that, nobody gets
// in for the rest of the hour and the plain busy page is shown, no captcha.
// Aggregate daily counter 'cap<bucket>ceiling' counts refusals at the ceiling.
function df_captcha_ceiling(int $cap): int {
    return max(0, (int)df_cfg('captcha_ceiling_mult', 2) - 1) * max(0, $cap);
}
function df_captcha_ceiling_hit(string $bucket, int $cap, ?int $now = null): bool {
    return df_hourly_count('capceil' . $bucket, $now) >= df_captcha_ceiling($cap);
}
// A solved token pays for one unit of $bucket (hourly cap $cap) past the cap:
// within the token's own hourly budget and the bucket's ceiling.
function df_captcha_pass(string $bucket, int $cap, ?int $now = null): bool {
    if (!df_captcha_enabled() || $cap <= 0) return false;
    $id = df_captcha_token_id(df_str($_COOKIE['df_cap'] ?? ''), $now);
    if ($id === null) return false;
    if (df_captcha_ceiling_hit($bucket, $cap, $now)) { df_daily_inc('cap' . $bucket . 'ceiling'); return false; }
    if (!df_hourly_inc_capped('captok' . $id, max(1, (int)df_cfg('captcha_token_budget', 30)), $now)) {
        df_daily_inc('capspent');
        return false;
    }
    // atomic reserve against the ceiling (a race past the check above lands here)
    if (df_hourly_inc_capped('capceil' . $bucket, max(1, df_captcha_ceiling($cap)), $now)
        && df_captcha_ceiling($cap) > 0) return true;
    df_daily_inc('cap' . $bucket . 'ceiling');
    return false;
}
// The same test without spending a unit (map.php's HTML page).
function df_captcha_token_left(?int $now = null): bool {
    $id = df_captcha_token_id(df_str($_COOKIE['df_cap'] ?? ''), $now);
    return $id !== null
        && df_hourly_count('captok' . $id, $now) < max(1, (int)df_cfg('captcha_token_budget', 30));
}
// Where to go back to after solving: a same-site relative path only. Anything
// else (absolute or scheme-relative URLs, backslashes, control characters,
// overlong) becomes "/" -- never an open redirect.
function df_captcha_return(string $r): string {
    if ($r === '' || strlen($r) > 2000 || $r[0] !== '/' || (isset($r[1]) && ($r[1] === '/' || $r[1] === '\\'))
        || preg_match('/[\x00-\x20\x7f\\\\]/', $r)) return '/';
    return $r;
}
// The captcha form page (HTML 2.0: an <img> and a form, no JS or CSS needed).
function df_captcha_form(string $return, string $msg = ''): string {
    $c = df_captcha_new();
    return page_head(DUCKFIND_NAME . ' - quick check', true)
       . '<h1>Busy right now -- quick check</h1>'
       . ($msg !== '' ? '<p><b>' . e($msg) . '</b></p>' : '')
       . '<p>' . DUCKFIND_NAME . ' is getting more traffic than usual, so this hour&#39;s shared '
       . 'budget for this feature is used up. Type the letters in the picture to carry on '
       . '(good for an hour), or try again after the top of the hour.</p>'
       . '<form action="/captcha.php" method="post">'
       . '<p><img src="/captcha.php?c=' . e($c) . '" width="200" height="60" alt="[Picture of '
       . DF_CAPTCHA_LEN . ' letters. If your browser can&#39;t show pictures, please try again '
       . 'after the top of the hour.]"></p>'
       . '<input type="hidden" name="c" value="' . e($c) . '">'
       . '<input type="hidden" name="r" value="' . e(df_captcha_return($return)) . '">'
       . '<p>Letters: <input type="text" name="a" size="8" maxlength="12"> '
       . '<input type="submit" value="Continue"></p></form>'
       . '<p><a href="/">Back to search</a></p>' . page_foot();
}
// Over-cap response for an HTML page: the captcha (503, so scripts see a
// refusal) when enabled; returns without output when disabled or when this
// bucket's token ceiling is reached, so the caller falls through to its plain
// busy page.
// Text-mode browsers can't show the captcha picture at all: they get the plain
// "try after the hour" busy page instead of a form they can't complete
// (2026-11-12). A UA guess only changes which refusal page is shown.
const DF_TEXT_BROWSER_RE = '/\b(?:lynx|w3m|e?links2?|browsh|retawq|edbrowse)\b/i';
function df_text_browser(): bool {
    return preg_match(DF_TEXT_BROWSER_RE, df_str($_SERVER['HTTP_USER_AGENT'] ?? '')) === 1;
}
function df_captcha_block(string $bucket, int $cap): void {
    if (!df_captcha_enabled()) return;
    if (df_text_browser()) return;                       // can't see the picture: plain busy page
    if (df_captcha_ceiling_hit($bucket, $cap)) return;   // ceiling reached: plain busy page for everyone
    http_response_code(503);
    header('Content-Type: text/html; charset=iso-8859-1');
    header('Cache-Control: no-store');
    header('Retry-After: ' . df_secs_to_next_hour());
    df_daily_inc('capshown');
    echo df_captcha_form(df_str($_SERVER['REQUEST_URI'] ?? '/'));
    exit;
}
// The captcha picture: the challenge's answer in GD's built-in font, scaled
// up with per-letter jitter, plus light noise. 200x60, 2-colour-ish GIF.
function df_captcha_gif(string $c): string {
    $ans = df_captcha_answer($c);
    $h = hash_hmac('sha256', 'captcha-art|' . $c, df_pob_secret(), true);   // jitter, not secret
    $im = imagecreatetruecolor(200, 60);
    imagefill($im, 0, 0, imagecolorallocate($im, 255, 255, 255));
    $ink = imagecolorallocate($im, 0, 0, 0);
    $grey = imagecolorallocate($im, 150, 150, 150);
    for ($i = 0; $i < DF_CAPTCHA_LEN; $i++) {
        $g = imagecreatetruecolor(10, 16);
        imagefill($g, 0, 0, imagecolorallocate($g, 255, 255, 255));
        imagestring($g, 5, 1, 0, $ans[$i], imagecolorallocate($g, 0, 0, 0));
        $dy = ord($h[$i]) % 14;
        $dx = ord($h[$i + 8]) % 6;
        imagecopyresized($im, $g, 12 + $i * 36 + $dx, 6 + $dy, 0, 0, 25, 40, 10, 16);
        unset($g);
    }
    for ($i = 0; $i < 4; $i++) {                 // a few thin lines across
        imageline($im, 0, ord($h[16 + $i]) % 60, 199, ord($h[20 + $i]) % 60, $grey);
    }
    for ($i = 0; $i < 160; $i++) {               // speckle
        imagesetpixel($im, ord($h[$i % 32]) * 7 % 200 + 0, ($i * 37 + ord($h[($i + 3) % 32])) % 60, $ink);
    }
    imagetruecolortopalette($im, false, 4);
    ob_start(); imagegif($im); $gif = (string)ob_get_clean();
    unset($im);
    return $gif;
}

// --- Search fallback: Brave Search API (added 2026-11-12) -------------------
// Used only when DuckDuckGo gave no usable answer for a search (both
// endpoints backing off, blocked or unreadable) -- Derek's pick, 2026-11-12.
// Paid per request ($5 per 1,000, with $5 of monthly credit), so it has its
// own daily cap on top of the shared hourly search cap: 'brave_daily_cap'
// (default 100, 0 = never use Brave). The key is 'brave_api_key' in the
// server's own config file, never in the repo; empty = fallback off.
// Brave's API terms allow only transient storage of results, so nothing here
// is cached. The API sees the server's address and the query, never the
// visitor's. A 429 (rate or quota) backs the 'brave' endpoint off like a DDG
// block. Aggregate daily counter 'brave' = Brave requests made.
const DF_BRAVE_API = 'https://api.search.brave.com/res/v1/web/search';
function df_brave_enabled(): bool {
    return (string)df_cfg('brave_api_key', '') !== '' && (int)df_cfg('brave_daily_cap', 100) > 0;
}
// JSON body -> [['title','url','snippet']] (the shape parse_ddg returns), or
// null when the body is not a Brave web-search response. Results live in
// web.results[] {title, url, description} (Brave's web-search docs); a
// response with no "web" block is a genuine "no results".
function df_brave_parse(string $json): ?array {
    $j = json_decode($json, true);
    if (!is_array($j) || ($j['type'] ?? 'search') !== 'search') return null;
    $out = [];
    foreach ((array)($j['web']['results'] ?? []) as $r) {
        if (!is_array($r)) continue;
        $url = (string)($r['url'] ?? '');
        if (!preg_match('#^https?://#i', $url)) continue;
        // the docs don't say whether description carries markup: strip it either way
        $clean = function ($v): string {
            return trim(preg_replace('/\s+/u', ' ', html_entity_decode(strip_tags((string)$v), ENT_QUOTES | ENT_HTML5, 'UTF-8')) ?? '');
        };
        $title = $clean($r['title'] ?? '');
        $out[] = ['title' => $title !== '' ? $title : $url, 'url' => $url, 'snippet' => $clean($r['description'] ?? '')];
        if (count($out) >= 30) break;
    }
    return $out;
}
// The search backend's name for user-facing text: 'Brave Search' when Brave
// is the primary backend, else 'DuckDuckGo'.
function df_search_engine_name(): string {
    return df_search_primary() === 'brave' ? 'Brave Search' : 'DuckDuckGo';
}
// ...and its home page, for the footer's "search powered by" link.
function df_search_engine_url(): string {
    return df_search_primary() === 'brave' ? 'https://brave.com/search/' : 'https://duckduckgo.com/';
}
// Which backend a search asks first (added 2026-11-12, Derek: "switch to brave
// entirely with ddg on backburner"). 'search_primary' = 'brave' (default) or
// 'ddg'; 'brave' only takes effect when Brave is configured (key + cap), so a
// server with no key keeps searching DDG. 'ddg_enabled' = false turns DDG
// search off entirely -- honoured only while Brave is usable, so search can
// never be left with no backend at all.
function df_search_primary(): string {
    return (df_cfg('search_primary', 'brave') === 'brave' && df_brave_enabled()) ? 'brave' : 'ddg';
}
function df_ddg_enabled(): bool {
    return (bool)df_cfg('ddg_enabled', true) || !df_brave_enabled();
}
// One Brave attempt for a search, with all its gates: Brave configured and not
// backing off, a unit of the shared hourly 'search' cap, a unit of its own
// 'brave_daily_cap'. Returns the results (possibly empty: a genuine "no
// results"), 'hourly' when the shared hourly cap refused, or null when Brave
// is off, backing off, over its daily cap, or failed.
function df_brave_attempt(string $q, int $s) {
    if (!df_brave_enabled() || df_ddg_backoff_remaining('brave') > 0) return null;
    if (!df_search_budget_ok()) return 'hourly';
    if (!df_daily_inc_capped('brave', (int)df_cfg('brave_daily_cap', 100))) return null;
    return df_brave_search($q, $s);
}
// One Brave request for $q at result offset $s (DDG-style: 0, 10, 20, ...;
// Brave's offset counts pages of 'count' results, 0..9). Returns results
// (possibly empty: a genuine "no results") or null on any failure. The
// caller has already reserved the hourly and daily units.
function df_brave_search(string $q, int $s = 0): ?array {
    $url = DF_BRAVE_API . '?q=' . urlencode($q) . '&count=10&offset=' . min(9, intdiv(max(0, $s), 10));
    $headers = ['Accept: application/json',
                'X-Subscription-Token: ' . (string)df_cfg('brave_api_key', '')];
    // Test seam: tests/run.php sets this to a callable instead of touching the network.
    $r = isset($GLOBALS['DF_TEST_BRAVE']) ? ($GLOBALS['DF_TEST_BRAVE'])($url, $headers)
                                          : http_get($url, 1000000, '', null, 8, $headers);
    if ($r === null) return null;
    if ((int)($r['status'] ?? 0) === 429) { df_ddg_backoff_hit('brave'); return null; }
    if ((int)($r['status'] ?? 0) !== 200) return null;
    $res = df_brave_parse((string)$r['body']);
    if ($res !== null) df_ddg_backoff_clear('brave');
    return $res;
}

// --- Reader: render fallback for JavaScript-built pages (added 2026-11-12) -----
// read.php asks a headless-Chromium service (services/render/, on kamino,
// reached like the !watch relay: 'render_url' + the shared 'relay_secret')
// for a live page whose own HTML extracts to almost no text. The service has
// its own address policy and limits; this side adds an hourly cap
// ('render_hourly_cap', default 60; a solved captcha token may add to it up to
// its ceiling), a 'render' endpoint backoff (503/504/unreachable), a 30-minute
// cache of rendered pages ('render:<url>'), and aggregate daily counters only:
// render (requests made), renderok (render used), renderfail, rendercapped.
// 'render_ua_mode' = 'chrome' (default) | 'honest' picks the service's
// user agent. Off when render_url or relay_secret is empty.
//
// Bot and JS *challenge* interstitials (as opposed to a plain "enable
// JavaScript" notice, which is just a JS-built page): never rendered, and
// shown as "blocked" by read.php.
// "ad blocker" and "access denied" only in the phrasings walls use (2026-11-12):
// a short legitimate page that merely mentions them (xkcd's footer, docs about
// permissions) is not a block page.
const DF_CHALLENGE_RE = '/just a moment|checking your browser|'
    . '(disable|turn off|pause|whitelist|allowlist)( your| any| the)? ad ?blockers?|ad ?blocker (detected|is (on|enabled|active))|'
    . 'attention required|verify (you are|that you are) human|cf-browser-verification|'
    . '(^|\W)access denied(\W{0,5}(you|your|reference|error|\|)|\s*$)|error 1020|you.{0,3}ve been blocked|blocked by|security (check|service)|'
    . 'unusual traffic|are you a (robot|human)|human verification|captcha|'
    . 'continue shopping|automated (access|requests)|requests from your|'
    . 'please enable cookies|temporarily unavailable|not a robot/i';
// Challenge pages recognisable from the raw body (2026-11-12 top-sites survey):
// AWS WAF (IMDb: awsWafCookieDomainList / gokuProps, HTTP 202), Anubis
// proof-of-work (/.within.website/), Reddit's JS proof-of-work form (fills a
// "solution" field and submits itself). Their visible text is too thin or too
// generic for DF_CHALLENGE_RE.
const DF_RAW_CHALLENGE_RE = '#awsWafCookieDomainList|gokuProps|/\.within\.website/|namedItem\("solution"\)#';
function df_raw_challenge(string $body): bool {
    return preg_match(DF_RAW_CHALLENGE_RE, substr($body, 0, 200000)) === 1;
}
function df_render_enabled(): bool {
    return trim((string)df_cfg('render_url', '')) !== '' && trim((string)df_cfg('relay_secret', '')) !== '';
}
function df_render_budget_ok(?int $now = null): bool {
    $cap = (int)df_cfg('render_hourly_cap', 60);
    if (df_hourly_inc_capped('render', $cap, $now)) return true;
    if (df_captcha_pass('render', $cap, $now)) return true;   // solved captcha, token budget left
    df_daily_inc('rendercapped');
    return false;
}
// Rendered DOM for $url: ['html' => ..., 'final_url' => ...], 'capped' when
// this hour's render budget is spent, or null (off, backing off, failed,
// refused by the service).
// Rendered output that is really an error screen (2026-11-12: wowhead's
// "Static CDN Error ... can't reach the server where we host our styles")
// is a failed render, not a page: otherwise "longer wins" would show it.
const DF_RENDER_ERROR_RE = '/static cdn error|can.t reach the server where we host|'
    . 'application error: a client-side exception|this page could(?:n.t| not) be loaded|'
    . 'failed to load (?:the )?(?:page|app|application)|chunkloaderror|loading chunk \\d+ failed/i';
function df_render_is_error(string $html): bool {
    $text = trim(preg_replace('/\s+/', ' ', strip_tags(preg_replace('#<(script|style)[^>]*>.*?</\1>#is', ' ', $html))) ?? '');
    return strlen($text) < 4000 && preg_match(DF_RENDER_ERROR_RE, $text) === 1;
}
// Returns the rendered page ['html', 'final_url'], 'capped' (render hour spent),
// 'failed' (the service was asked and gave no usable page), 'unavailable'
// (render is backing off after recent failures), or null (render not set up).
function df_render_fetch(string $url) {
    $key = 'render:' . $url;
    if (($c = df_cache_get($key, 1800)) !== null) {
        $d = @unserialize($c, ['allowed_classes' => false]);
        if (is_array($d) && isset($d['html'])) return $d;
    }
    if (!df_render_enabled()) return null;
    if (df_ddg_backoff_remaining('render') > 0) return 'unavailable';
    if (!df_render_budget_ok()) return 'capped';
    df_daily_inc('render');
    $mode = df_cfg('render_ua_mode', 'chrome') === 'honest' ? 'honest' : 'chrome';
    $endpoint = rtrim((string)df_cfg('render_url', ''), '/') . '/render';
    $payload = json_encode(['url' => $url, 'ua' => $mode]);
    $headers = ['Content-Type: application/json', 'X-Relay-Secret: ' . trim((string)df_cfg('relay_secret', ''))];
    // Test seam: tests/run.php sets this to a callable instead of touching the network.
    if (isset($GLOBALS['DF_TEST_RENDER'])) {
        $r = ($GLOBALS['DF_TEST_RENDER'])($endpoint, (string)$payload, $headers);
    } else {
        // A fixed, trusted backend (like watch.php's relay calls), not the
        // SSRF-guarded http_get(): the service does its own address checks.
        $r = null;
        if (function_exists('curl_init')) {
            $ch = curl_init($endpoint);
            curl_setopt_array($ch, [
                CURLOPT_POST           => true,
                CURLOPT_POSTFIELDS     => (string)$payload,
                CURLOPT_HTTPHEADER     => $headers,
                CURLOPT_CONNECTTIMEOUT => 5,
                CURLOPT_TIMEOUT        => 15,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_PROTOCOLS      => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            ]);
            $body = curl_exec($ch);
            $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            unset($ch);
            if ($body !== false) $r = ['status' => $status, 'body' => (string)$body];
        }
    }
    $st = $r === null ? 0 : (int)($r['status'] ?? 0);
    $j = $r === null ? null : json_decode((string)($r['body'] ?? ''), true);
    if ($st === 200 && is_array($j) && ($j['status'] ?? '') === 'ok' && is_string($j['html'] ?? null)
        && !df_render_is_error($j['html'])) {
        $out = ['html' => $j['html'], 'final_url' => is_string($j['final_url'] ?? null) ? $j['final_url'] : $url];
        df_cache_put($key, serialize($out));
        df_ddg_backoff_clear('render');
        return $out;
    }
    df_daily_inc('renderfail');
    // the service is busy, timed out or unreachable: leave it alone for a while
    if ($st === 0 || $st === 429 || $st === 503 || $st === 504) df_ddg_backoff_hit('render');
    return 'failed';
}

function df_ftp_budget_block(): void {
    df_captcha_block('ftp', (int)df_cfg('ftp_hourly_cap', 200));                                  // returns only when the captcha is off
    http_response_code(503);
    header('Content-Type: text/html; charset=iso-8859-1');
    header('Retry-After: ' . df_secs_to_next_hour());
    echo page_head(DUCKFIND_NAME . ' - ftp busy', true) . '<h1>FTP gateway is busy</h1>'
       . '<p>The FTP gateway only makes a limited number of FTP fetches each hour, shared '
       . 'by everyone, and this hour&#39;s are used up. Please try again after the top of '
       . 'the hour. The rest of ' . DUCKFIND_NAME . ' works as usual.</p>'
       . '<p><a href="/">Back to search</a></p>' . page_foot();
    exit;
}

// --- Streaming concurrency cap (added 2026-11-07) ----------------------------
// dl.php, ftp.php's file stream and watch.php's ?dl=1 relay each hold a php-fpm
// worker for up to 5-15 minutes. Per-IP RATE limits don't bound that: 20 starts
// a minute from one address is enough to occupy every worker in the small pool
// and take the whole site down. This caps how many such streams run AT ONCE,
// per client and site-wide, so streams can never starve ordinary pages.
//
// Slots are flock()ed files in the rate dir. A held lock is the slot; there is
// no counter to drift out of sync. The kernel drops the lock when the file is
// closed or the process dies, so a client abort, a fatal error or a killed
// worker can never leak a slot. df_slot_release() also closes them explicitly
// (and runs at shutdown) so a worker is free the moment its stream ends.
//
// Privacy: per-client slot files are named with the same salted hash as the
// rate-limit files ("slot_<hash>_<n>", empty, expired by df_rl_gc() like any
// other rate file). Site-wide slots are dotfiles (".slotg_<n>"), which carry no
// client identity and which the GC glob skips, so it never unlinks a live one.
// Nothing else is written. Fails OPEN on a filesystem error, like df_rate_ok().
function df_slot_try(string $path_prefix, int $n) {
    for ($i = 0; $i < $n; $i++) {
        $f = $path_prefix . $i;
        $fp = @fopen($f, 'c');
        if ($fp === false) return true;                      // FS error: fail open
        if (flock($fp, LOCK_EX | LOCK_NB)) { @touch($f); return $fp; }
        fclose($fp);
    }
    return null;                                             // every slot is held
}

// Acquire one per-client and one site-wide streaming slot. Returns 0 when the
// request may go ahead, 429 when this client already has its maximum running,
// or 503 when the site-wide cap is full. Call df_slot_block($code) on non-zero.
function df_slot_acquire(): int {
    $per    = max(1, (int)df_cfg('stream_max_per_client', 2));
    $global = max(1, (int)df_cfg('stream_max_global', 4));
    $dir = df_rate_dir();
    $mine = df_slot_try($dir . '/slot_' . sha1(df_rl_salt($dir) . df_client_ip()) . '_', $per);
    if ($mine === null) return 429;
    $site = df_slot_try($dir . '/.slotg_', $global);
    if ($site === null) {
        if (is_resource($mine)) { flock($mine, LOCK_UN); fclose($mine); }
        return 503;
    }
    static $registered = false;
    if (!$registered) { register_shutdown_function('df_slot_release'); $registered = true; }
    foreach ([$mine, $site] as $fp) if (is_resource($fp)) $GLOBALS['DF_SLOTS'][] = $fp;
    return 0;
}

// Release every slot this request holds. Safe to call more than once.
function df_slot_release(): void {
    foreach ($GLOBALS['DF_SLOTS'] ?? [] as $fp) {
        if (is_resource($fp)) { flock($fp, LOCK_UN); fclose($fp); }
    }
    $GLOBALS['DF_SLOTS'] = [];
}

function df_slot_block(int $code): void {
    http_response_code($code === 503 ? 503 : 429);
    header('Content-Type: text/html; charset=iso-8859-1');
    header('Retry-After: 60');
    if ($code === 503) {
        echo page_head('Busy') . '<h1>Too many downloads right now</h1>'
           . '<p>DuckFind only runs a few long downloads at a time so the rest of the site '
           . 'stays up. Please try again in a minute.</p>' . page_foot();
    } else {
        echo page_head('Slow down') . '<h1>Too many downloads at once</h1>'
           . '<p>You already have the maximum number of downloads running. Let one finish, '
           . 'then try again.</p>' . page_foot();
    }
    exit;
}

// ===========================================================================
// Output helpers
// ===========================================================================

// Transliterate typographic Unicode that ISO-8859-1-era browsers can't show
// (smart quotes, dashes, ellipsis...) into plain ASCII equivalents.
function df_translit(string $s): string {
    static $map = [
        "\u{2018}" => "'",  "\u{2019}" => "'",  "\u{201A}" => "'",  "\u{2032}" => "'",
        "\u{201C}" => '"',  "\u{201D}" => '"',  "\u{201E}" => '"',  "\u{2033}" => '"',
        "\u{2013}" => '-',  "\u{2014}" => '--', "\u{2015}" => '--', "\u{2212}" => '-',
        "\u{2026}" => '...', "\u{00A0}" => ' ', "\u{2022}" => '*',  "\u{00B7}" => '*',
        "\u{200B}" => '',   "\u{FEFF}" => '',
    ];
    return strtr($s, $map);
}

// Numeric-entity every non-ASCII codepoint, astral plane included. NOT
// mb_encode_numericentity() -- confirmed live (2026-10-09) that PHP's own
// implementation mishandles any codepoint >= U+10000 (emoji, rare CJK): it
// internally goes through UTF-16 surrogate-pair arithmetic even when told
// UTF-8, and emits (codepoint - 0x10000) instead of the real codepoint, a
// long-standing PHP core defect, not a convmap misconfiguration -- the
// convmap used here, [0x80, 0x10FFFF, 0, 0x10FFFF], is the standard
// identity-offset pattern and still hits it. preg_replace_callback + mb_ord
// computes the real codepoint directly per character, sidestepping the bug
// entirely.
function df_numeric_entities(string $s): string {
    return preg_replace_callback('/[\x{80}-\x{10FFFF}]/u', function ($m) {
        return '&#' . mb_ord($m[0], 'UTF-8') . ';';
    }, $s) ?? $s;
}

// entity-encode a plain string for safe ancient-browser output (result is ASCII)
function e(string $s): string {
    $s = htmlspecialchars(df_translit($s), ENT_QUOTES, 'UTF-8');
    return df_numeric_entities($s);
}

// numeric-entity all non-ASCII chars in a string that already contains HTML tags
function ascii_html(string $html): string {
    return df_numeric_entities(df_translit($html));
}

// Visitor's theme choice (cookie).
function df_dark(): bool {
    return (($_COOKIE['df_theme'] ?? '') === 'dark');
}

// <body> colour attributes for the current theme. Dark mode uses the Dracula
// palette (soft dark blue-grey, not harsh black).
function df_body_colors(): string {
    return df_dark()
        ? 'bgcolor="#282A36" text="#F8F8F2" link="#8BE9FD" vlink="#BD93F9"'
        : 'bgcolor="#FFFFFF" text="#000000" link="#0000CC" vlink="#551A8B"';
}

// Theme-aware accent colours so they stay legible on either background.
function df_url_color(): string   { return df_dark() ? '#50FA7B' : '#007700'; }  // result URLs
function df_muted_color(): string { return df_dark() ? '#6272A4' : '#777777'; }  // captions/source tags

// Base reading size for body text. Default 2: Verdana's big x-height reads a
// full size larger than the old browser-default serif, so size 2 Verdana is
// about right on an 800x600 vintage screen (size 3 looked oversized).
// "Larger" (3) is a cookie-backed setting (see settings.php).
function df_text_size(): string {
    return (($_COOKIE['df_text'] ?? 'normal') === 'large') ? '3' : '2';
}

// Shorten a long string for DISPLAY with a trailing "..." (the link href stays
// full). URLs have no spaces to wrap on, so an un-truncated one forces the fixed
// 600px column wider and triggers horizontal scroll on a vintage screen.
function df_shorten(string $s, int $max = 68): string {
    return mb_strlen($s) > $max ? mb_substr($s, 0, $max - 3) . '...' : $s;
}

// Normalise an image colour-mode value (query param or cookie) to color/gray/bw.
// The is_string guard makes it crash-safe against array-typed input (?im[]=x,
// which otherwise TypeErrors strtolower() into a 500).
function df_img_mode($v): string {
    $v = is_string($v) ? strtolower($v) : '';
    return in_array($v, ['gray', 'bw'], true) ? $v : 'color';
}

// ===========================================================================
// ASCII-art image mode (added 2026-11-08)
// ===========================================================================
// A third way to show images, for browsers with no <img> at all (Lynx,
// MacWeb, MacLynx): the PAGE fetches the image and inlines it as text art in
// a <pre>. df_img_mode() above stays the GIF renderers' normaliser (img.php,
// map.php, pdf.php), where 'ascii' means nothing and falls back to colour;
// pages that embed images use df_page_img_mode(), which also allows 'ascii'.
function df_page_img_mode($v): string {
    return (is_string($v) && strtolower($v) === 'ascii') ? 'ascii' : df_img_mode($v);
}

// Shared fetch -> validate -> decode for a remote image, used by img.php's
// GIF path and the inline ASCII path. The CALLER must already have charged the
// 'img' rate bucket and passed the browser-proof gate. Applies:
//   - the SSRF-checked fetch (http_get / df_wayback_get, each hop re-validated
//     and IP-pinned) with the img_fetch_cap byte cap;
//   - an image/* content-type check;
//   - the decompression-bomb guard: a tiny compressed file can declare enormous
//     dimensions and GD would allocate w*h*4 bytes decoding it, so dimensions
//     are read from the header BEFORE decoding and refused over 12 MP (or if
//     unreadable, e.g. AVIF). 12 MP keeps
//     peak GD memory (~w*h*4 = 48 MB) under PHP's 128 MB default even with a
//     few concurrent decodes on the 1 GB box.
// Failures are negative-cached 15 min under imgfail: so a dead image isn't
// refetched per viewer -- EXCEPT a fetch that failed under a shortened
// $timeout (the inline path's page budget), which says nothing about the
// image itself. $timeout 0 = the normal DUCKFIND_TIMEOUT.
// The imgfail key carries the Wayback era (df_imgfail_key): a throttled Wayback
// fetch must not blank the live image (or another year's copy) of the same
// URL, and vice versa. Live keys stay "imgfail:<url>".
function df_imgfail_key(string $url, string $year = ''): string {
    return 'imgfail:' . ($year !== '' ? $year . ':' : '') . $url;
}
// Decode a Windows .ico (as served at /favicon.ico) into a GD image -- GD has
// no ICO reader. Picks the frame closest to $want px (preferring >= $want and
// deeper colour). Handles PNG frames and 32/24/8/4/1-bit BMP/DIB frames with
// their AND transparency masks; a file that is really PNG/GIF/JPEG under an
// .ico name is handed to GD. Returns null for anything else. (Added 2026-11-12
// for the news favicon fallback; 16/16 real favicons decoded in testing.)
// Decompression-bomb guard (2026-11-12): GD's pixel buffers live outside PHP's
// memory_limit, so a small file declaring huge dimensions (a 124 KB PNG that
// decodes to 32000x32000 = 2.1 GB) must be refused from its header, before
// imagecreatefromstring() ever sees it. True if GD can read $b and its declared
// size is within $maxW x $maxH and $maxPx pixels; unknown formats are refused.
const DF_IMG_MAX_PIXELS = 12000000;
const DF_ICO_MAX_SIDE = 256;
function df_img_size_ok(string $b, int $maxPx = DF_IMG_MAX_PIXELS, int $maxW = PHP_INT_MAX, int $maxH = PHP_INT_MAX): bool {
    $info = @getimagesizefromstring($b);
    if ($info === false) return false;
    $w = (int)$info[0]; $h = (int)$info[1];
    return $w >= 1 && $h >= 1 && $w <= $maxW && $h <= $maxH && $w * $h <= $maxPx;
}
function df_ico_decode(string $b, int $want = 16): ?GdImage {
    if (strncmp($b, "\x89PNG\r\n\x1a\n", 8) === 0 || strncmp($b, 'GIF', 3) === 0 || strncmp($b, "\xFF\xD8", 2) === 0) {
        if (!df_img_size_ok($b)) return null;
        $g = @imagecreatefromstring($b);
        return $g === false ? null : $g;
    }
    if (strlen($b) < 6) return null;
    $h = unpack('vres/vtype/vcount', $b);
    if ($h['res'] !== 0 || $h['type'] !== 1 || $h['count'] < 1 || $h['count'] > 64) return null;
    $best = null; $bestScore = PHP_INT_MAX;
    for ($i = 0; $i < $h['count']; $i++) {
        $o = 6 + 16 * $i;
        if (strlen($b) < $o + 16) return null;
        $e = unpack('Cw/Ch/Ccc/Cr/vplanes/vbpp/Vsize/Voff', substr($b, $o, 16));
        $w = $e['w'] ?: 256;
        $score = abs($w - $want) * 100 + ($w < $want ? 50 : 0) - $e['bpp'];
        if ($score < $bestScore && $e['size'] > 0 && $e['off'] + $e['size'] <= strlen($b)) { $best = $e; $bestScore = $score; }
    }
    if (!$best) return null;
    $d = substr($b, $best['off'], $best['size']);
    if (strncmp($d, "\x89PNG\r\n\x1a\n", 8) === 0) {
        // the directory entry's size byte is not binding: check the PNG's own IHDR
        $pi = @getimagesizefromstring($d);
        if ($pi === false || $pi[2] !== IMAGETYPE_PNG
            || !df_img_size_ok($d, DF_ICO_MAX_SIDE * DF_ICO_MAX_SIDE, DF_ICO_MAX_SIDE, DF_ICO_MAX_SIDE)) return null;
        $g = @imagecreatefromstring($d);
        return $g === false ? null : $g;
    }
    if (strlen($d) < 40) return null;
    $bi = unpack('Vhs/lw/lh/vplanes/vbpp/Vcomp', substr($d, 0, 20));
    $w = $bi['w']; $hh = intdiv(abs($bi['h']), 2); $bpp = $bi['bpp'];
    if ($w < 1 || $w > DF_ICO_MAX_SIDE || $hh < 1 || $hh > DF_ICO_MAX_SIDE || $bi['comp'] !== 0 || !in_array($bpp, [1, 4, 8, 24, 32], true)) return null;
    $p = $bi['hs']; $pal = [];
    if ($bpp <= 8) {
        $n = 1 << $bpp;
        if (strlen($d) < $p + 4 * $n) return null;
        for ($i = 0; $i < $n; $i++) { $c = substr($d, $p + 4 * $i, 4); $pal[] = [ord($c[2]), ord($c[1]), ord($c[0])]; }
        $p += 4 * $n;
    }
    $stride = intdiv($w * $bpp + 31, 32) * 4;
    $mstride = intdiv($w + 31, 32) * 4;
    $mp = $p + $stride * $hh;
    if (strlen($d) < $p + $stride * $hh) return null;
    $im = imagecreatetruecolor($w, $hh);
    imagealphablending($im, false);
    imagesavealpha($im, true);
    $hasAlpha = false;
    if ($bpp === 32) {
        for ($y = 0; $y < $hh && !$hasAlpha; $y++) for ($x = 0; $x < $w; $x++) {
            if (ord($d[$p + $y * $stride + 4 * $x + 3])) { $hasAlpha = true; break; }
        }
    }
    for ($y = 0; $y < $hh; $y++) {
        $row = $p + ($hh - 1 - $y) * $stride;
        $mrow = $mp + ($hh - 1 - $y) * $mstride;
        for ($x = 0; $x < $w; $x++) {
            $a = 0;
            if ($bpp === 32) {
                $o = $row + 4 * $x;
                [$bb, $g, $r, $al] = [ord($d[$o]), ord($d[$o + 1]), ord($d[$o + 2]), ord($d[$o + 3])];
                if ($hasAlpha) $a = 127 - ($al >> 1);
            } elseif ($bpp === 24) {
                $o = $row + 3 * $x;
                [$bb, $g, $r] = [ord($d[$o]), ord($d[$o + 1]), ord($d[$o + 2])];
            } else {
                $bit = $x * $bpp;
                $byte = ord($d[$row + ($bit >> 3)]);
                $idx = ($byte >> (8 - $bpp - ($bit & 7))) & ((1 << $bpp) - 1);
                [$r, $g, $bb] = $pal[$idx] ?? [0, 0, 0];
            }
            if (!$hasAlpha && isset($d[$mrow + ($x >> 3)]) && ((ord($d[$mrow + ($x >> 3)]) >> (7 - ($x & 7))) & 1)) $a = 127;
            imagesetpixel($im, $x, $y, imagecolorallocatealpha($im, $r, $g, $bb, $a));
        }
    }
    return $im;
}

// Favicon links for the news river (fav.php). The token binds the host only, so
// fav.php can't be used as an open favicon proxy or to mint cache files for
// arbitrary hosts -- only hosts duckfind itself put on a page get an icon.
function df_fav_token(string $host): string {
    return substr(hash_hmac('sha256', 'fav|' . strtolower($host), df_pob_secret()), 0, 16);
}
// The public/ directory (this file's), for pages that load local assets.
function df_public_dir(): string {
    return __DIR__;
}
function df_fav_host(string $url): string {
    $h = strtolower((string)(parse_url($url, PHP_URL_HOST) ?? ''));
    return preg_match('/^[a-z0-9.-]{1,253}$/', $h) && strpos($h, '.') !== false ? $h : '';
}

function df_img_load(string $url, string $year = '', int $timeout = 0): ?GdImage {
    if (!preg_match('#^https?://#i', $url)) return null;
    if (df_cache_get(df_imgfail_key($url, $year), 900) !== null) return null;
    $cap = (int)df_cfg('img_fetch_cap', 8000000);
    if ($year !== '') {   // Wayback: the era-correct archived image
        $ts = strlen($year) === 4 ? $year . '0601' : $year;
        $ts = substr(str_pad($ts, 14, '0'), 0, 14);
        $res = df_wayback_get($ts, $url, 604800, $cap, $timeout);
    } else {
        $res = http_get($url, $cap, '', null, $timeout);
    }
    if ($res === null) {
        if ($timeout <= 0) df_cache_put(df_imgfail_key($url, $year), '1');
        return null;
    }
    $img = null;
    if (strncmp((string)$res['body'], "\x00\x00\x01\x00", 4) === 0) {   // .ico (GD can't read it)
        $img = df_ico_decode((string)$res['body']);
    } elseif (preg_match('#^image/#i', (string)$res['ctype'])) {
        if (df_img_size_ok((string)$res['body'])) {
            $src = @imagecreatefromstring($res['body']);
            if ($src !== false) $img = $src;
        }
    }
    if ($img === null) df_cache_put(df_imgfail_key($url, $year), '1');
    return $img;
}

// Dark-to-light density ramp: on the default white page the DARK pixels must
// be the dense characters ('@'), and white is a blank. Pure printable ASCII,
// none of it HTML-special (escaping happens anyway, for custom ramps).
const DF_ASCII_RAMP = ' .:-=+*#%@';
// Monospace cells are about twice as tall as wide, so each text row covers
// two pixel rows' worth of height: rows = height/width * cols * 0.5.
const DF_ASCII_ASPECT = 0.5;
// Sub-samples per character cell (columns x rows) for df_ascii_art.
const DF_ASCII_SX = 3;
const DF_ASCII_SY = 6;
// Minimum tonal range (of 255) before auto-levels stretches an image.
const DF_ASCII_LEVELS_GATE = 16;
// Smallest image worth drawing inline: under this many pixels on either side,
// or under DF_ASCII_MIN_ROWS rows of art (banners), the page shows the
// image's alt text instead -- a 32px icon or an 88x31 button is noise as art.
const DF_ASCII_MIN_PX = 64;
const DF_ASCII_MIN_ROWS = 5;
// Bump when the art changes, so cached art from older code isn't served.
const DF_ASCII_VERSION = 2;

// Convert a GD image to ASCII art. Pure: GD image in, string out (the input
// image is not modified). Returns the art's lines joined by "\n", trailing
// blanks trimmed per line, HTML-escaped and printable ASCII only -- ready to
// drop inside <pre>...</pre>.
//   $cols    target width in characters (never upscales past the pixel width)
//   $darkBg  the page is light-on-dark (dark theme): bright pixels get the
//            dense characters instead, and transparency composites on black
//   $maxRows tall images are capped at this many rows, narrowing the width to
//            keep the aspect ratio
// Transparency is composited onto the page background first (white by
// default), so a transparent PNG's empty area comes out blank, not as noise.
function df_ascii_art(GdImage $src, int $cols = 40, bool $darkBg = false,
                      string $ramp = DF_ASCII_RAMP, int $maxRows = 40): string {
    $ramp = preg_replace('/[^\x20-\x7E]/', '', $ramp) ?? '';
    if (strlen($ramp) < 2) $ramp = DF_ASCII_RAMP;
    $n = strlen($ramp);
    $sw = imagesx($src); $sh = imagesy($src);
    $cols = max(1, min($cols, $sw));
    $maxRows = max(1, $maxRows);
    $rows = max(1, (int)round($sh / $sw * $cols * DF_ASCII_ASPECT));
    if ($rows > $maxRows) {
        $rows = $maxRows;
        $cols = max(1, min($cols, (int)round($maxRows / DF_ASCII_ASPECT * $sw / $sh)));
    }
    // Resample into a canvas of DF_ASCII_SX x DF_ASCII_SY sub-samples per
    // character cell that KEEPS alpha (blending off), then composite each
    // sub-sample against the background by hand. The sub-samples let thin
    // lines, which barely move a cell's average, still be seen (line art).
    $SX = DF_ASCII_SX; $SY = DF_ASCII_SY;
    $W = $cols * $SX; $H = $rows * $SY;
    $t = imagecreatetruecolor($W, $H);
    imagealphablending($t, false);
    imagesavealpha($t, true);
    imagefilledrectangle($t, 0, 0, $W - 1, $H - 1, imagecolorallocatealpha($t, 0, 0, 0, 127));
    imagecopyresampled($t, $src, 0, 0, 0, 0, $W, $H, $sw, $sh);
    $bg = $darkBg ? 0.0 : 255.0;
    $S = [];
    for ($y = 0; $y < $H; $y++) {
        for ($x = 0; $x < $W; $x++) {
            $c = imagecolorat($t, $x, $y);
            $a = (($c >> 24) & 0x7F) / 127;                          // 0 opaque .. 1 clear
            $lum = 0.299 * (($c >> 16) & 0xFF) + 0.587 * (($c >> 8) & 0xFF) + 0.114 * ($c & 0xFF);
            $S[] = $lum * (1 - $a) + $bg * $a;                       // composite on page bg
        }
    }
    unset($t);
    $cellMean = function (array $V, int $cx, int $cy) use ($SX, $SY, $W): float {
        $sum = 0.0;
        for ($j = 0; $j < $SY; $j++) {
            $base = ($cy * $SY + $j) * $W + $cx * $SX;
            for ($k = 0; $k < $SX; $k++) $sum += $V[$base + $k];
        }
        return $sum / ($SX * $SY);
    };
    $L = [];
    for ($cy = 0; $cy < $rows; $cy++) for ($cx = 0; $cx < $cols; $cx++) $L[] = $cellMean($S, $cx, $cy);
    // Auto-levels: a photo's tones usually sit in a narrow mid band, which a
    // 10-step ramp turns into a wall of one character. Stretch the 2nd..98th
    // percentile of the cell tones to the full range -- only when there IS
    // real tonal range (>= DF_ASCII_LEVELS_GATE of 255), so a flat or
    // near-flat image keeps its true density. (The gate was 48 until
    // 2026-11-12; a foggy or low-contrast photo spanning 112..150 then came
    // out as two characters.)
    $sorted = $L; sort($sorted);
    $cnt = count($sorted);
    $lo = $sorted[(int)floor(($cnt - 1) * 0.02)];
    $hi = $sorted[(int)ceil(($cnt - 1) * 0.98)];
    $stretch = ($hi - $lo) >= DF_ASCII_LEVELS_GATE;
    // Paper whitening (2026-11-12): when one tone dominates on the paper side
    // of the image (scans, sepia or grey line drawings, diagrams), that tone
    // IS the paper -- clip it to blank, and take the ink end from the
    // SUB-samples so thin strokes still reach the dense characters. With
    // very little ink (> 70% paper) it is line art: shape glyphs (below).
    $isLine = false;
    $hist = array_fill(0, 32, 0);
    foreach ($L as $v) $hist[min(31, (int)($v / 8))]++;
    $mi = (int)array_keys($hist, max($hist))[0];
    $near = 0;
    for ($k = max(0, $mi - 2); $k <= min(31, $mi + 2); $k++) $near += $hist[$k];
    $mode = min(255, $mi * 8 + 4);
    $ss = $S; sort($ss); $sc = count($ss);
    $slo = $ss[(int)floor(($sc - 1) * 0.01)];
    $shi = $ss[(int)ceil(($sc - 1) * 0.99)];
    $inkDark = !$darkBg;                                     // light page: dark pixels are ink
    $paperSide = $inkDark ? ($mode > ($slo + $shi) / 2) : ($mode < ($slo + $shi) / 2);
    if ($near / $cnt > 0.55 && $paperSide && ($shi - $slo) >= 32) {
        if ($inkDark) { $hi = $mode - 10; $lo = min($slo, $hi - 16); }
        else          { $lo = $mode + 10; $hi = max($shi, $lo + 16); }
        $stretch = true;
        $isLine = $near / $cnt > 0.70;
    }
    // per-sub-sample ink density 0..1, then per cell
    $D = [];
    foreach ($S as $v) {
        $l = $stretch ? ($v - $lo) * 255 / ($hi - $lo) : $v;
        $d = $inkDark ? 1 - $l / 255 : $l / 255;
        $D[] = max(0.0, min(1.0, $d));
    }
    $shapes = $isLine && $ramp === DF_ASCII_RAMP;           // glyph set assumes the default ramp
    $lines = [];
    for ($cy = 0; $cy < $rows; $cy++) {
        $line = '';
        for ($cx = 0; $cx < $cols; $cx++) {
            $ch = $shapes ? df_ascii_shape($D, $W, $cx, $cy) : null;
            if ($ch === null) $ch = $ramp[(int)round($cellMean($D, $cx, $cy) * ($n - 1))];
            $line .= $ch;
        }
        $lines[] = htmlspecialchars(rtrim($line, ' '), ENT_QUOTES, 'ISO-8859-1');
    }
    return implode("\n", $lines);
}

// Line-art glyph for one cell: look at WHERE the ink sits among its
// DF_ASCII_SX x DF_ASCII_SY sub-samples ($D: densities 0..1, row width $W)
// and pick a character with that shape: | - _ / \ + ' " . : (dense cells
// fall back to # @ * +). Used only for images that are mostly paper.
function df_ascii_shape(array $D, int $W, int $cx, int $cy): string {
    $SX = DF_ASCII_SX; $SY = DF_ASCII_SY;
    $t = 0.22; $cnt = 0; $tot = 0.0;
    $colHit = array_fill(0, $SX, 0); $rowHit = array_fill(0, $SY, 0);
    $sxy = 0.0; $sx = 0.0; $sy = 0.0; $sxx = 0.0; $syy = 0.0;
    for ($j = 0; $j < $SY; $j++) {
        for ($k = 0; $k < $SX; $k++) {
            $d = $D[($cy * $SY + $j) * $W + $cx * $SX + $k];
            $tot += $d;
            if ($d > $t) {
                $cnt++; $colHit[$k]++; $rowHit[$j]++;
                $yy = $j / 2.0;                                  // sub-samples are ~2x taller than wide
                $sx += $k; $sy += $yy; $sxx += $k * $k; $syy += $yy * $yy; $sxy += $k * $yy;
            }
        }
    }
    $mean = $tot / ($SX * $SY);
    if ($cnt === 0) return $mean > 0.06 ? '.' : ' ';
    if ($mean > 0.75) return '@';
    if ($mean > 0.5) return '#';
    $colsUsed = count(array_filter($colHit)); $rowsUsed = count(array_filter($rowHit));
    $fullCol = max($colHit) >= $SY - 1;                          // a column inked top to bottom
    $fullRow = max($rowHit) >= $SX;                              // a row inked side to side
    if ($fullCol && $fullRow && $cnt <= $SX + $SY + 2) return '+';
    if ($fullCol && $colsUsed <= 2 && $cnt <= $SY * 2) return '|';
    if ($fullRow && $rowsUsed <= 3) {
        $r = (int)array_search(max($rowHit), $rowHit);
        return $r >= $SY - 2 ? '_' : ($r <= 0 ? '"' : '-');
    }
    if ($cnt >= 3) {
        $mx = $sx / $cnt; $my = $sy / $cnt;
        $vx = $sxx / $cnt - $mx * $mx; $vy = $syy / $cnt - $my * $my; $cv = $sxy / $cnt - $mx * $my;
        if ($vx > 0.2 && $vy > 0.2) {
            $corr = $cv / sqrt($vx * $vy);
            if ($corr > 0.6) return '\\';
            if ($corr < -0.6) return '/';
        }
        if ($vy > 4 * $vx && $rowsUsed >= 4) return '|';
        if ($vx > 2 * $vy && $rowsUsed <= 2) return '-';
    }
    if ($cnt <= 2) {
        $r = (int)array_search(max($rowHit), $rowHit);
        return $r < 2 ? "'" : ($r >= $SY - 2 ? '.' : ':');
    }
    return $mean > 0.33 ? '*' : ($mean > 0.18 ? '+' : ':');
}

// Per-page bounds for the inline path. A page does its image fetches
// synchronously while rendering, so a page full of images must not turn into
// dozens of slow fetches:
//   ascii_max_per_page  at most this many images become art (default 8);
//   ascii_time_budget   seconds of wall clock for ALL of a page's fetches,
//                       counted from its first ASCII image (default 6). A fetch
//                       only starts with >= 2 s left, and is given only the
//                       time that remains, so the worst case is about budget+1 s.
// Cache hits cost no fetch, but still count toward the per-page cap (bounds
// the page size for a slow link: 8 x <= 40x40 chars). Everything past a bound
// gets its text fallback (alt text / an [image] link to the GIF).
const DF_ASCII_COLS = 40;

// Art for one image on a page in 'ascii' mode, with every protection img.php
// applies, in img.php's order: 'img' rate bucket, art cache, negative cache,
// browser-proof gate, then the shared df_img_load() fetch/caps/decode. The
// gate can't redirect mid-page (headers are gone), so it's checked without
// one: no valid df_pob cookie (and not a cookieless vintage browser, which
// img.php also lets through) -> cached art only, never a fetch -- exactly
// img.php's rule (cache hits ungated, fetches gated). The pages that call this
// already ran df_require_browser_proof() before their own fetch (read.php),
// so in practice a real visitor has the cookie or a vintage UA.
// Returns the <pre> block; '' for an image too tiny to be content (spacers,
// pixels -- the caller shows nothing); null when it couldn't be inlined (the
// caller shows its fallback). Art is cached 7 days, like the GIFs.
function df_ascii_inline(string $url, string $year = ''): ?string {
    static $count = 0, $deadline = null, $rateOut = false;
    if (!preg_match('#^https?://#i', $url)) return null;
    if ($count >= (int)df_cfg('ascii_max_per_page', 8) || $rateOut) return null;
    if ($deadline === null) $deadline = microtime(true) + (float)df_cfg('ascii_time_budget', 6);
    if (!df_rate('img')) { $rateOut = true; return null; }

    $dark = df_dark();
    $ckey = 'ascii' . DF_ASCII_VERSION . ':' . DF_ASCII_COLS . ':' . ($dark ? 'd' : 'l') . ':' . $year . ':' . $url;
    if (($hit = df_cache_get($ckey, 604800)) !== null) {
        if ($hit !== '') $count++;
        return $hit;
    }
    if (df_cache_get(df_imgfail_key($url, $year), 900) !== null) return null;
    if (!df_pob_pass()) return null;

    $remain = $deadline - microtime(true);
    if ($remain < 2) return null;                          // page budget spent
    $img = df_img_load($url, $year, (int)min(DUCKFIND_TIMEOUT, floor($remain)));
    if ($img === null) return null;
    if (imagesx($img) < 16 || imagesy($img) < 16) {        // spacer / tracking pixel
        df_cache_put($ckey, '');
        return '';
    }
    if (!df_ascii_worth_drawing(imagesx($img), imagesy($img), DF_ASCII_COLS)) {
        unset($img);                                       // icon, button, banner:
        return null;                                       // the caller shows its alt-text fallback
    }
    $pre = '<pre>' . df_ascii_art($img, DF_ASCII_COLS, $dark) . '</pre>';
    unset($img);
    df_cache_put($ckey, $pre);
    $count++;
    return $pre;
}

// Whether an image of $w x $h px is worth drawing as art at $cols columns:
// not when either side is under DF_ASCII_MIN_PX (icons, 88x31 buttons) or
// the art would be under DF_ASCII_MIN_ROWS rows (728x90 banners) -- those
// come out as unreadable noise, and their alt text says more.
function df_ascii_worth_drawing(int $w, int $h, int $cols = DF_ASCII_COLS): bool {
    if ($w < DF_ASCII_MIN_PX || $h < DF_ASCII_MIN_PX) return false;
    $c = max(1, min($cols, $w));
    return (int)round($h / $w * $c * DF_ASCII_ASPECT) >= DF_ASCII_MIN_ROWS;
}

// The text an image gets when it isn't inlined: its alt text (or "image"),
// in brackets, linked to the GIF so a browser that can open images
// externally (Lynx can) still reaches it. $link=false inside another <a>
// (no nested anchors).
function df_ascii_fallback(string $url, string $alt, bool $link = true): string {
    $t = '[' . e($alt !== '' ? 'image: ' . $alt : 'image') . ']';
    return $link ? '<a href="/img.php?url=' . htmlspecialchars(urlencode($url), ENT_QUOTES) . '">' . $t . '</a>' : $t;
}

// True if a DOM node sits inside an <a> (its fallback must then not be a link).
function df_in_link(DOMNode $node): bool {
    for ($p = $node->parentNode; $p !== null; $p = $p->parentNode) {
        if ($p->nodeType === XML_ELEMENT_NODE && strtolower($p->nodeName) === 'a') return true;
    }
    return false;
}

// <pre> may not sit inside <a> (HTML 2/3.2), and a 20-line link is useless in
// Lynx anyway: lift any art out of a link's contents, ahead of the link, and
// keep the link on whatever text is left (or "[link]" if it was only an image).
// $open is the already-escaped opening <a ...> tag.
function df_ascii_hoist(string $open, string $inner): string {
    if (strpos($inner, '<pre>') === false) return $open . $inner . '</a>';
    preg_match_all('#<pre>.*?</pre>#s', $inner, $m);
    $rest = trim((string)preg_replace('#<pre>.*?</pre>#s', '', $inner));
    $restText = trim(strip_tags(str_replace(['<br>', '&nbsp;'], ' ', $rest)));
    return implode('', $m[0]) . $open . ($restText !== '' ? $rest : '[link]') . '</a>';
}

// $desc, when given on an indexable landing page, adds a meta description +
// OpenGraph tags for search engines and social cards (ignored by old browsers).
// A host-wide 'noindex_all' config (set on the mirror) keeps duplicate content
// out of the index so only the primary site is ranked.
// $headExtra is ALREADY-ESCAPED markup placed just before </head> (e.g. the
// reader's <link rel="prev">); callers must escape every value in it.
function page_head(string $title, bool $noindex = false, string $desc = '', string $headExtra = ''): string {
    $t = e($title);
    $ni = $noindex || df_cfg('noindex_all', false);
    $robots = $ni ? "<meta name=\"robots\" content=\"noindex,nofollow\">\n" : '';
    $seo = '';
    if ($desc !== '' && !$ni) {
        $d = e($desc);
        $base = rtrim((string)df_cfg('base_url', 'http://duckfind.com'), '/');
        $seo = "<meta name=\"description\" content=\"$d\">\n"
             . "<meta property=\"og:title\" content=\"$t\">\n"
             . "<meta property=\"og:description\" content=\"$d\">\n"
             . "<meta property=\"og:type\" content=\"website\">\n"
             . "<meta property=\"og:image\" content=\"$base/duck.gif?v=4\">\n";
    }
    return "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">\n"
         . "<html><head><title>$t</title>\n"
         . "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=iso-8859-1\">\n"
         . "<link rel=\"shortcut icon\" href=\"/favicon.gif?v=4\" type=\"image/gif\">\n"
         . "<link rel=\"search\" type=\"application/opensearchdescription+xml\" title=\"" . e(DUCKFIND_NAME) . "\" href=\"/opensearch.php\">\n"
         . $seo . $robots . $headExtra
         // theme comes from the cookie; on vintage browsers dark mode is just the
         // classic <body> colour attributes (HTML 3.2, works everywhere)
         . "</head><body " . df_body_colors() . ">\n"
         // Centred 600px column: wide enough to read, narrow enough to fit a
         // 640x480 screen (Win 3.1 / Classilla) without horizontal scroll, and
         // it keeps the content — and the footer rule — from spanning the whole
         // width of a modern browser. (760px, the old value, overflowed 640x480.)
         . "<table width=\"600\" align=\"center\" border=\"0\" cellpadding=\"8\" cellspacing=\"0\"><tr><td>\n"
         // A screen-legible sans-serif reads far better than the default serif
         // at small vintage sizes. Verdana leads — its big x-height + wide
         // spacing read larger/clearer at a given size (present on Mac OS 9 via
         // IE, and on Windows); Geneva is the guaranteed classic-Mac fallback.
         // Nested <font> tags override the size but inherit the face.
         . "<font face=\"Verdana, Geneva, Helvetica, Arial, sans-serif\" size=\"" . df_text_size() . "\">\n";
}

function page_foot(bool $tagline = true, bool $navRow = true): string {
    // The no-logs claim is only honest if the whole host cooperates (no access
    // logs, no logging proxy in front), so it stays off unless the operator
    // affirms it in config (see privacy_claims in config.example.php).
    // Brand links home so error pages that print only the footer (read.php
    // failures, rate-limit, ask.php) always have a way back to the site.
    $privacy = df_cfg('privacy_claims', false)
        ? "<br>no ads &middot; no tracking &middot; no logging"
        : "";
    // Panel-vote decision 2026-10-07: a page deep in the site (e.g. map.php)
    // had no one-click path to guestbook.php specifically -- it's the one
    // feature with no bang-shortcut equivalent, so even the shortcuts panel
    // doesn't cover it. Reuses the exact small nav row the homepage already
    // carries (not the larger bang-duplicate row that got reverted) rather
    // than inventing a new one. $navRow=false on index.php's own bare-landing
    // branch, which already renders this same row itself up top -- same
    // duplication guard as $tagline above.
    $nav = $navRow
        ? '<p><font size="1"><a href="/news.php">news</a> &nbsp;&middot;&nbsp; '
        . '<a href="/feeds.php">my feeds</a> &nbsp;&middot;&nbsp; '
        . '<a href="/map.php">maps</a> &nbsp;&middot;&nbsp; '
        . '<a href="/read.php">reader</a> &nbsp;&middot;&nbsp; '
        . '<a href="/guestbook.php">guestbook</a> &nbsp;&middot;&nbsp; '
        . '<a href="/?q=!help">shortcuts</a></font></p>'
        : '';
    // $tagline=false skips the "the modern web in plain HTML..." line -- the
    // bare homepage already says the same thing as its own hero tagline right
    // under the logo, so the footer repeating it right below is pure
    // duplication on that one page specifically. Drop the <br> along with it
    // so "DuckFind" doesn't sit alone on its own line -- it joins the links
    // line below instead of leaving an orphaned word above an empty gap.
    return "\n<hr>\n" . $nav . "<p align=\"center\"><font size=\"1\">" . df_brand_link(false)
         . ($tagline ? " -- the modern web in plain HTML, for vintage browsers<br>" : " &middot; ")
         . "<a href=\"/settings.php\">settings</a> &middot; "
         . "<a href=\"/about.php\">about</a> &middot; "
         . "search powered by <a href=\"" . df_search_engine_url() . "\">" . df_search_engine_name() . "</a>"
         . $privacy . "</font></p>\n"
         . "</font></td></tr></table>\n</body></html>";   // close the base-size font from page_head
}

// Fetch and parse an RSS 2.0 / RSS 1.0 (RDF) / Atom feed into [title, link, ts]
// items, cached 30 minutes (shared across all users of the same feed). The cache
// always holds up to 15 items regardless of $limit -- the key is per-URL, so
// caching a shorter slice would starve later callers that want more.
// Since 2026-11-12:
//  - a failed fetch, a recent failure (10-min negative cache) or the site-wide
//    hourly feed cap all fall back to the cached copy up to a day old instead
//    of returning nothing (a flaky feed no longer drops off the page);
//  - RSS 1.0 / RDF feeds (Slashdot, DW, Nature) are parsed (items at the root,
//    dc:date) -- they used to parse "successfully" as zero items;
//  - $timeout (seconds, 0 = default) bounds this one fetch inside a page budget;
//  - 'comments' carries an item's discussion URL (RSS <comments>);
//  - a description that is only "Comments" (Hacker News's feed) is dropped;
//  - future-dated items are clamped to now.
function df_feed_items(string $url, int $limit, int $timeout = 0): array {
    $limit = min($limit, 15);
    if (($c = df_cache_get('feed2:' . $url, 1800)) !== null) {
        $d = @unserialize($c, ["allowed_classes" => false]);
        if (is_array($d)) return array_slice($d, 0, $limit);
    }
    // short negative cache: this feed failed recently -- don't refetch it on
    // every reload for ~10 min (same idea as img.php's imgfail:). A reader full
    // of dead or slow feed URLs otherwise costs a fresh timeout per feed per load.
    if (df_cache_get('feedfail:' . $url, 600) !== null) return df_feed_items_stale($url, $limit);
    // site-wide hourly budget on uncached feed fetches (My Feeds lets visitors
    // add arbitrary URLs); over it, the cached copy is served
    if (!df_feed_budget_ok()) return df_feed_items_stale($url, $limit);
    $want  = $limit;
    $limit = 15;
    $out = [];
    $ok  = false;
    $r = http_get($url, 2000000, '', null, max(0, $timeout));
    if ($r !== null && (int)($r['status'] ?? 200) < 400) {
        $parsed = df_feed_parse((string)$r['body'], $limit);
        if ($parsed !== null) { $ok = true; $out = $parsed; }
    }
    $out = array_values(array_filter($out,
        fn($i) => $i['title'] !== '' && preg_match('#^https?://#i', $i['link'])));
    if ($ok) {
        df_cache_put('feed2:' . $url, serialize($out));   // don't cache transient failures...
        return array_slice($out, 0, $want);
    }
    df_cache_put('feedfail:' . $url, '1');                // ...beyond the 10-min negative entry
    df_daily_inc('feedfail');
    return df_feed_items_stale($url, $want);              // and show the last good copy meanwhile
}

// Parse an RSS 2.0 / RSS 1.0 (RDF) / Atom document into up to $limit raw items
// (not yet filtered for title/link). null when the body isn't XML; [] for XML
// without items. Split out of df_feed_items (2026-11-12) so it can be tested.
function df_feed_parse(string $body, int $limit = 15): ?array {
    $out = [];
    $xml = @simplexml_load_string($body, 'SimpleXMLElement', LIBXML_NOCDATA | LIBXML_NONET);
    if ($xml !== false) {
        $rss1 = $xml->children('http://purl.org/rss/1.0/');
        if (isset($xml->channel->item)) {                 // RSS 2.0
            foreach ($xml->channel->item as $it) {
                $desc = (string)$it->description;
                // full HTML often lives in content:encoded, not description
                $cenc = (string)$it->children('http://purl.org/rss/1.0/modules/content/')->encoded;
                $out[] = [
                    'title'    => df_feed_title((string)$it->title),
                    'link'     => trim((string)$it->link),
                    'ts'       => df_feed_ts((string)$it->pubDate
                                  ?: (string)$it->children('http://purl.org/dc/elements/1.1/')->date),
                    'desc'     => df_feed_desc($desc !== '' ? $desc : $cenc),
                    'img'      => df_feed_img($it, $cenc . ' ' . $desc),
                    'comments' => trim((string)$it->comments),
                ];
                if (count($out) >= $limit) break;
            }
        } elseif (isset($rss1->item)) {                    // RSS 1.0 / RDF
            foreach ($rss1->item as $it) {
                $desc = (string)$it->description;
                $cenc = (string)$it->children('http://purl.org/rss/1.0/modules/content/')->encoded;
                $out[] = [
                    'title'    => df_feed_title((string)$it->title),
                    'link'     => trim((string)$it->link),
                    'ts'       => df_feed_ts((string)$it->children('http://purl.org/dc/elements/1.1/')->date),
                    'desc'     => df_feed_desc($desc !== '' ? $desc : $cenc),
                    'img'      => df_feed_img($it, $cenc . ' ' . $desc),
                    'comments' => '',
                ];
                if (count($out) >= $limit) break;
            }
        } elseif (isset($xml->entry)) {                    // Atom
            foreach ($xml->entry as $en) {
                $link = '';
                foreach ($en->link as $l) {
                    $rel = (string)($l['rel'] ?? 'alternate');
                    if ($rel === 'alternate' || $link === '') $link = (string)$l['href'];
                }
                $when = (string)($en->published ?? '') ?: (string)($en->updated ?? '');
                $sum = (string)($en->summary ?? '');
                $con = (string)($en->content ?? '');
                $out[] = ['title' => df_feed_title((string)$en->title), 'link' => $link,
                          'ts' => df_feed_ts($when),
                          'desc' => df_feed_desc($sum !== '' ? $sum : $con),
                          'img'  => df_feed_img($en, $con . ' ' . $sum),
                          'comments' => ''];
                if (count($out) >= $limit) break;
            }
        }
    }
    return $xml === false ? null : $out;
}

// Site-wide hourly budget on uncached feed fetches ('feed_hourly_cap', 0 = off;
// aggregate daily counter 'feedcapped' on refusal). Same shape as the other
// hourly caps (lib.php df_hourly_inc_capped).
function df_feed_budget_ok(?int $now = null): bool {
    if (df_hourly_inc_capped('feed', (int)df_cfg('feed_hourly_cap', 120), $now)) return true;
    df_daily_inc('feedcapped');
    return false;
}

// Feed date -> unix time; 0 when missing or unparseable; clamped to now when
// the feed claims a time more than an hour in the future (bad clocks, embargoes).
function df_feed_ts(string $when): int {
    $ts = strtotime(trim($when)) ?: 0;
    return ($ts > time() + 3600) ? time() : $ts;
}

// df_feed_text, minus descriptions that carry nothing: Hacker News's feed
// description is just a "Comments" link.
function df_feed_desc(string $html): string {
    $t = df_feed_text($html);
    return preg_match('/^\s*comments?\s*$/i', $t) ? '' : $t;
}

// Fair mixing for a section: newest first, at most $perSource items from any
// one source, $total items in all. If the cap leaves the section short (few
// sources), the remaining slots are filled with the newest leftovers.
function df_feed_mix(array $items, int $perSource = 3, int $total = 10): array {
    usort($items, fn($a, $b) => ($b['ts'] ?? 0) <=> ($a['ts'] ?? 0));
    $out = []; $rest = []; $n = [];
    foreach ($items as $it) {
        $src = (string)($it['src'] ?? '');
        if (($n[$src] ?? 0) < $perSource && count($out) < $total) { $out[] = $it; $n[$src] = ($n[$src] ?? 0) + 1; }
        else $rest[] = $it;
    }
    foreach ($rest as $it) { if (count($out) >= $total) break; $out[] = $it; }
    usort($out, fn($a, $b) => ($b['ts'] ?? 0) <=> ($a['ts'] ?? 0));
    return $out;
}

// --- News "Top stories" (added 2026-11-12) ---------------------------------
// Sections show the newest items only, so a big story a few hours old was pushed
// out by fresher minor ones (the Microsoft/Outlook outage was in the HN and
// Register feeds but never on the page). The Top box above the sections keeps:
//   (a) a story several sources are covering: headlines clustered across all
//       sections by shared significant words, from >= 2 different sources;
//   (b) a story high on a ranked feed: the Hacker News front-page feed is in
//       rank order, so its top 3 by feed position ('rank' 0..2).
// Ranked by number of sources, then HN rank, then recency.
const DF_NEWS_STOP = ['the','a','an','and','or','but','of','to','in','on','for','at','by','with','from','as','is',
    'are','was','were','be','been','has','have','had','it','its','this','that','these','those','after','over',
    'into','about','new','says','say','said','how','why','what','who','when','will','can','could','would','not',
    'up','out','more','than','just','now','your','you','we','our','they','their','his','her','he','she','i',
    'show','ask','hn','video','watch','live','update','updates','report','reports','via','amid','gets','get'];
function df_news_words(string $title): array {
    $t = mb_strtolower(html_entity_decode($title, ENT_QUOTES | ENT_HTML5, 'UTF-8'));
    $t = preg_replace("/['\x{2019}]s\b/u", '', $t) ?? $t;            // possessive 's
    $t = preg_replace('/[^\p{L}\p{N}]+/u', ' ', $t) ?? $t;
    $out = [];
    foreach (preg_split('/\s+/', trim($t)) ?: [] as $w) {
        if (mb_strlen($w) < 3 || in_array($w, DF_NEWS_STOP, true)) continue;
        if (mb_strlen($w) > 4 && substr($w, -1) === 's' && substr($w, -2) !== 'ss') $w = substr($w, 0, -1);   // crude plural
        $out[$w] = true;
    }
    return array_keys($out);
}
// Two headlines are the same story if they share >= 3 significant words, or their
// word sets overlap with Jaccard >= 0.35 (and share at least 2 words).
function df_news_same(array $a, array $b): bool {
    if (!$a || !$b) return false;
    $shared = count(array_intersect($a, $b));
    if ($shared >= 3) return true;
    return $shared >= 2 && $shared / count(array_unique(array_merge($a, $b))) >= 0.35;
}
// Items (title, link, ts, src, optional rank) from every section -> up to $max
// top stories: ['item' => newest item of the cluster, 'also' => [other sources]].
function df_news_top(array $items, int $max = 6): array {
    usort($items, fn($a, $b) => ($b['ts'] ?? 0) <=> ($a['ts'] ?? 0));
    $clusters = [];
    foreach ($items as $it) {
        $w = df_news_words((string)($it['title'] ?? ''));
        if (!$w) continue;
        $placed = false;
        foreach ($clusters as &$c) {
            // compare with the cluster's first headline only: growing the word set
            // with every member snowballed loosely related stories together
            if (df_news_same($c['words'], $w)) {
                $c['items'][] = $it;
                $placed = true; break;
            }
        }
        unset($c);
        if (!$placed) $clusters[] = ['words' => $w, 'items' => [$it]];
    }
    $top = [];
    foreach ($clusters as $c) {
        $srcs = [];
        $rank = 99;
        foreach ($c['items'] as $it) {
            $srcs[(string)($it['src'] ?? '')] = true;
            if (isset($it['rank'])) $rank = min($rank, (int)$it['rank']);
        }
        $n = count($srcs);
        if ($n < 2 && $rank > 2) continue;
        // lead headline: the most central one (shares the most words with the
        // rest of the cluster), newest on a tie -- not a side angle that
        // happens to be newest
        $lead = $c['items'][0]; $best = -1;
        if (count($c['items']) > 2) {
            $ws = array_map(fn($x) => df_news_words((string)($x['title'] ?? '')), $c['items']);
            foreach ($c['items'] as $i => $x) {
                $score = 0;
                foreach ($ws as $j => $wj) if ($j !== $i) $score += count(array_intersect($ws[$i], $wj)) / max(1, count($ws[$i]));
                if ($score > $best) { $best = $score; $lead = $x; }   // items are newest-first: ties keep the newer
            }
        }
        $also = array_values(array_diff(array_keys($srcs), [(string)($lead['src'] ?? '')]));
        $top[] = ['item' => $lead, 'also' => $also, 'n' => $n, 'rank' => $rank];
    }
    usort($top, function ($a, $b) {
        return [$b['n'], $a['rank'], $b['item']['ts'] ?? 0] <=> [$a['n'], $b['rank'], $a['item']['ts'] ?? 0];
    });
    return array_slice($top, 0, $max);
}
// The Top box: one line per story, linking to the (signed) reader like the river.
// "; also: A, B, C, D +5 more" -- a big story can be carried by ten outlets,
// and listing all of them wraps to several lines on a 512px screen.
function df_news_also(array $also, int $show = 4): string {
    if (!$also) return '';
    $more = count($also) - $show;
    return '; also: ' . e(implode(', ', array_slice($also, 0, $show))) . ($more > 0 ? ' +' . $more . ' more' : '');
}
function df_news_top_html(array $top): string {
    if (!$top) return '';
    // same layout as every other section (Derek 2026-11-12): thumbnail or
    // placeholder, headline, source and time, summary -- plus the also line
    $items = [];
    foreach ($top as $t) $items[] = ['also' => (array)($t['also'] ?? [])] + (array)$t['item'];
    return '<h2>Top stories</h2>' . df_river($items, true);
}

// A lighter version of a news article, where the publisher runs one: NPR's
// text-only site (an article went from ~160 KB to ~5 KB). Unknown URLs pass
// through unchanged.
function df_text_version_url(string $url): string {
    $p = parse_url($url);
    $host = strtolower((string)($p['host'] ?? ''));
    $path = (string)($p['path'] ?? '');
    if ($host === 'www.npr.org' || $host === 'npr.org') {
        if (preg_match('#/(nx-s\d+-\d+)(?:/|$)#', $path, $m)) return 'https://text.npr.org/' . $m[1];
        if (preg_match('#^/\d{4}/\d{2}/\d{2}/(\d{6,})(?:/|$)#', $path, $m)) return 'https://text.npr.org/' . $m[1];
    }
    return $url;
}

// Hacker News item id from an item's comments URL (news.ycombinator.com/item?id=N), or 0.
function df_hn_item_id(string $url): int {
    if (preg_match('#^https?://news\.ycombinator\.com/item\?id=(\d{1,10})$#i', trim($url), $m)) return (int)$m[1];
    return 0;
}

// Cache-only variant: returns whatever copy exists (up to a day old) without
// ever touching the network. Used when a page's fetch budget is spent.
function df_feed_items_stale(string $url, int $limit): array {
    if (($c = df_cache_get('feed2:' . $url, 86400)) !== null) {
        $d = @unserialize($c, ["allowed_classes" => false]);
        if (is_array($d)) return array_slice($d, 0, min($limit, 15));
    }
    return [];
}

// Entry summary as plain text, tags stripped, trimmed to a headline-card length.
function df_feed_text(string $html): string {
    $t = trim(preg_replace('/\s+/', ' ',
        html_entity_decode(strip_tags($html), ENT_QUOTES | ENT_HTML5, 'UTF-8')));
    return mb_strlen($t) > 200 ? mb_substr($t, 0, 197) . '...' : $t;
}

// Entry title, same entity-decode as df_feed_text -- some feeds (The Verge's
// among them) ship titles with HTML entities (&#8217; etc.) already written
// into the XML text content; SimpleXML only unescapes the outer &amp; wrapper
// during parsing, leaving the literal "&#8217;" string behind, which e()'s
// own escaping then re-escaped into the visibly broken "&amp;#8217;" Derek
// spotted live. Titles don't carry markup, so no strip_tags needed here.
function df_feed_title(string $raw): string {
    return trim(html_entity_decode(trim($raw), ENT_QUOTES | ENT_HTML5, 'UTF-8'));
}

// Best-effort item image: RSS enclosure, then media:thumbnail/content (MRSS
// namespace, used by BBC & most news feeds), then the first <img> in the
// entry's own HTML. Empty string when there is none.
function df_feed_img($node, string $descHtml = ''): string {
    foreach ($node->enclosure as $en) {
        $u = (string)$en['url'];
        if (preg_match('#^image/#i', (string)$en['type']) && preg_match('#^https?://#i', $u)) return $u;
    }
    // MRSS thumbnail/content, incl. nested inside <media:group> (YouTube etc.)
    $media = $node->children('http://search.yahoo.com/mrss/');
    // preserve_keys=false: SimpleXML keys every child by its tag name, so the
    // default keyed copy collapses several <media:group>s into the last one,
    // and spreading string keys is a fatal Error on PHP 8.0 (README minimum).
    foreach ([$media, ...iterator_to_array($media->group, false)] as $scope) {
        $s = $scope === $media ? $media : $scope->children('http://search.yahoo.com/mrss/');
        foreach (['thumbnail', 'content'] as $tag) {
            foreach ($s->$tag as $m) {
                // attributes() is required here: [] lookups on elements fetched via
                // children(ns) resolve in that namespace and miss plain attributes
                $u = (string)($m->attributes()['url'] ?? '');
                if (preg_match('#^https?://#i', $u)) return $u;
            }
        }
    }
    if ($descHtml !== '') {
        if (preg_match('/<img[^>]+src=["\']?(https?:\/\/[^"\'\s>]+)/i', $descHtml, $m)) return $m[1];
        // lazy-loaded content images keep the real URL in a data-* attribute
        if (preg_match('/<img[^>]+data-(?:src|original|lazy-src)=["\']?(https?:\/\/[^"\'\s>]+)/i', $descHtml, $m)) return $m[1];
    }
    return '';
}

// Fallback thumbnail for a feed item with no inline image: fetch a small slice
// of the article and read its og:image / twitter:image (or first content <img>).
// Cached 7 days per article (empty results too, so image-less articles aren't
// refetched), and network fetches are bounded PER REQUEST — cached lookups are
// free and always applied, only uncached ones spend the budget. Keeps an
// image-heavy news page from turning into dozens of article fetches on a miss.
function df_og_image(string $url): string {
    static $budget = 8;
    static $deadline = null;
    // Aggregate wall-clock cap across ALL enrichment this request: without it, a
    // hostile feed of image-less items pointing at slow hosts (unique URLs to
    // defeat the cache) could spend budget x per-fetch-timeout ~= many seconds
    // and pin a worker. Cap total enrichment to a few seconds.
    if ($deadline === null) $deadline = microtime(true) + 4.0;
    if (!preg_match('#^https?://#i', $url)) return '';
    $key = 'ogimg:' . $url;
    $c = df_cache_get($key, 604800);
    if ($c !== null) return $c;                 // cached (incl. '') — free, always used
    if ($budget <= 0 || microtime(true) >= $deadline) return '';   // count or time budget spent
    $budget--;
    $r = http_get($url, 60000, '', null, 3);    // <head> is enough; short 3s time budget
    if ($r === null || ($r['status'] ?? 200) >= 400) return '';   // don't cache a transient failure
    $b = $r['body'];
    $img = '';
    if (preg_match('/<meta[^>]+(?:property|name)=["\'](?:og:image|twitter:image)(?::src)?["\'][^>]*content=["\']([^"\']+)/i', $b, $m)
        || preg_match('/<meta[^>]+content=["\']([^"\']+)["\'][^>]*(?:property|name)=["\'](?:og:image|twitter:image)/i', $b, $m)) {
        $img = html_entity_decode($m[1]);
    } elseif (preg_match('/<img[^>]+src=["\']?(https?:\/\/[^"\'\s>]+)/i', $b, $m)) {
        $img = $m[1];
    }
    if ($img !== '' && !preg_match('#^https?://#i', $img)) $img = absolutize($url, $img);
    df_cache_put($key, $img);                   // cache the resolved result (incl. genuine '')
    return $img;
}

// True if a URL points at a file better downloaded than rendered (software,
// archives, media, office docs) — the reader routes these through dl.php so an
// old browser can actually fetch them over plain HTTP.
function df_is_download(string $url): bool {
    $ext = strtolower(pathinfo((string)parse_url($url, PHP_URL_PATH), PATHINFO_EXTENSION));
    if ($ext === '') return false;
    static $dl = ['sit','sitx','hqx','bin','sea','cpt','dsk','img','toast','dmg','iso','smi',
        'zip','gz','tgz','tar','z','lha','lzh','arc','arj','rar','7z','bz2','xz',
        'exe','msi','com','deb','rpm','pkg',
        'mp3','wav','aif','aiff','au','mid','midi','mod','flac','ogg','m4a',
        'mov','avi','mpg','mpeg','mp4','mkv','wmv',
        'doc','docx','rtf','xls','xlsx','ppt','pptx','odt','epub',
        'rom','nes','gb','gba','a26','d64'];
    return in_array($ext, $dl, true);
}

// ASCII-only anchor slug, so #fragment links match reliably on old browsers
// (raw %XX in fragments is matched inconsistently by 90s engines).
function df_slug(string $s): string {
    $s = strtolower(preg_replace('/[^a-z0-9]+/i', '-', $s));
    return trim($s, '-') ?: 'x';
}

// Render a list of feed/news items as a uniform "headline river": one table,
// one row per story, with a FIXED-WIDTH thumbnail column so every headline
// starts at the same x whether or not it has an image. The image column
// appears only when at least one item in the batch has an image (and the
// visitor allows images), so an all-text feed like Hacker News stays a clean
// list instead of a column of gaps. Missing image -> empty cell (alignment
// preserved); missing summary -> just the headline line (no hole). Honours the
// visitor's image on/off and colour-mode cookie. Items: title, link, src, ts,
// and optional img/desc (as produced by df_feed_items).
// ASCII image mode shows no thumbnail column at all: a news page is up to ~80
// thumbnails, and 88px art is unreadable mush that would multiply the page
// size and its fetches. Text-browser readers get the clean headline list, and
// the article's real images as art once they open it in the reader.
// The label for a news thumbnail's fallback tile (img.php ph=): the source
// name, printable ASCII only, at most 24 chars; '-' when there is none.
function df_ph_label(string $src): string {
    $l = trim(preg_replace('/ +/', ' ', preg_replace('/[^\x20-\x7e]/', '', preg_replace('/\s/', ' ', $src))));
    return $l === '' ? '-' : substr($l, 0, 24);
}
function df_river(array $items, bool $showDesc = true): string {
    if (!$items) return '';
    $pm     = df_page_img_mode($_COOKIE['df_mode'] ?? 'color');
    $imgOn  = (($_COOKIE['df_img'] ?? '1') !== '0') && $pm !== 'ascii';
    $imMode = ($pm === 'gray' || $pm === 'bw') ? '&amp;im=' . $pm : '';
    // og:image fallback for items whose feed carried no image (NPR, Al Jazeera,
    // Science Daily... put images only on the article page). Bounded + cached in
    // df_og_image; only runs when the visitor shows images.
    if ($imgOn) {
        foreach ($items as &$it) {
            if (($it['img'] ?? '') === '' && !empty($it['link'])) {
                $og = df_og_image((string)$it['link']);
                if ($og !== '') $it['img'] = $og;
            }
        }
        unset($it);
    }
    $col = false;
    if ($imgOn) foreach ($items as $it) if (($it['img'] ?? '') !== '') { $col = true; break; }

    // favicons (fav.php): the picture-column placeholder for items without an
    // image (Derek 2026-11-12: a placeholder, not a blank), only when the
    // visitor shows images. With them on, every row gets the picture column.
    $favOn = $imgOn && (bool)df_cfg('news_favicons', true);
    if ($favOn) $col = true;
    $favQs = ($pm === 'gray' || $pm === 'bw') ? '&amp;im=' . $pm : '';
    $o = '<table border="0" cellpadding="3" cellspacing="0" width="100%">';
    foreach ($items as $it) {
        $link = df_text_version_url((string)$it['link']);   // e.g. npr.org -> text.npr.org
        $ru = '/read.php?url=' . htmlspecialchars(urlencode($link), ENT_QUOTES)
            . df_readtok_qs($link, true);   // signed (df_readtok)
        $o .= '<tr>';
        if ($col) {
            $o .= '<td width="96" valign="top">';
            if (($it['img'] ?? '') !== '') {
                $o .= '<a href="' . $ru . '"><img src="/img.php?url='
                    . htmlspecialchars(urlencode($it['img']), ENT_QUOTES) . '&amp;w=88' . $imMode
                    . '&amp;ph=' . rawurlencode(df_ph_label((string)($it['src'] ?? ''))) . '" border="0" alt="*"></a>';
            } elseif ($favOn && ($fh = df_fav_host((string)$it['link'])) !== '') {
                $o .= '<center><a href="' . $ru . '"><img src="/fav.php?h=' . rawurlencode($fh) . '&amp;t='
                    . df_fav_token($fh) . $favQs . '" width="32" height="32" border="0" alt="*"></a></center>';
            }
            $o .= '</td>';
        }
        $hn = df_hn_item_id((string)($it['comments'] ?? ''));
        $o .= '<td valign="top"><a href="' . $ru . '"><b>' . e((string)$it['title']) . '</b></a>'
            . ' <font size="1" color="' . df_muted_color() . '">- ' . e((string)($it['src'] ?? ''))
            // time of day, not "3h ago": the news page is cached for an hour
            . (!empty($it['ts']) ? ', ' . gmdate('M j H:i', (int)$it['ts']) . ' UTC' : '')
            . ($hn > 0 ? ' &middot; <a href="/hn.php?id=' . $hn . '">comments</a>' : '')
            . (!empty($it['also']) ? df_news_also((array)$it['also']) : '')   // Top stories
            . '</font>';
        if ($showDesc && ($it['desc'] ?? '') !== '') {
            $o .= '<br><font size="2">' . e((string)$it['desc']) . '</font>';
        }
        $o .= '</td></tr>';
    }
    return $o . '</table>';
}

// A multi-page article's own pager links, as raw (possibly relative) hrefs:
// rel="next" and rel="prev" on <link> or <a>, first in document order. The
// HTML spec makes rel="previous" a synonym of "prev", so both count. Returns
// ['next' => '', 'prev' => ''] when there are none (prev is empty on page 1).
// Used by read.php's extract_readable(); lives here so tests/run.php can reach it.
function df_rel_pages(DOMXPath $xp): array {
    $out = ['next' => '', 'prev' => ''];
    // rel is a case-insensitive, space-separated token list: REL="NEXT" (1998
    // markup) and rel="next nofollow" both count. libxml already lowercases
    // the element and attribute names; this lowercases and tokenises the value.
    $tok = fn(string $t): string => 'contains(concat(" ", normalize-space(translate(@rel, '
        . '"ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")), " "), " ' . $t . ' ")';
    foreach (['next' => $tok('next'), 'prev' => $tok('prev') . ' or ' . $tok('previous')] as $k => $cond) {
        $nl = $xp->query('//link[' . $cond . ']/@href | //a[' . $cond . ']/@href');
        if ($nl !== false && $nl->length) $out[$k] = trim($nl->item(0)->nodeValue);
    }
    return $out;
}

// Resolve a possibly-relative URL against a base URL.
function absolutize(string $base, string $rel): string {
    $rel = trim($rel);
    if ($rel === '') return $base;
    if (preg_match('#^[a-z][a-z0-9+.\-]*:#i', $rel)) return $rel;      // has scheme
    if (strpos($rel, '//') === 0) {                                     // protocol-relative
        $bs = parse_url($base, PHP_URL_SCHEME) ?: 'https';
        return $bs . ':' . $rel;
    }
    $p = parse_url($base);
    if (!isset($p['scheme'], $p['host'])) return $rel;
    $port = isset($p['port']) ? ':' . $p['port'] : '';
    $path = $p['path'] ?? '/';
    $origin = $p['scheme'] . '://' . $p['host'] . $port;
    // fragment-only keeps the base query (RFC 3986 5.2.2); "?q" replaces it
    if ($rel[0] === '#') return $origin . $path . (isset($p['query']) ? '?' . $p['query'] : '') . $rel;
    if ($rel[0] === '?') return $origin . $path . $rel;
    // Dot-segment cleanup applies to the PATH only: split off ?query/#fragment
    // first, or "/go?u=https://x.org/" had its "//" collapsed to "https:/x.org".
    $suffix = '';
    if (preg_match('/[?#]/', $rel, $qm, PREG_OFFSET_CAPTURE)) {
        $suffix = substr($rel, $qm[0][1]);
        $rel = substr($rel, 0, $qm[0][1]);
    }
    $abspath = ($rel[0] === '/') ? $rel : preg_replace('#/[^/]*$#', '/', $path) . $rel;
    $parts = explode('/', $abspath);
    $segments = [];
    foreach ($parts as $seg) {
        if ($seg === '..') array_pop($segments);
        elseif ($seg !== '.' && $seg !== '') $segments[] = $seg;
    }
    // keep a directory's trailing slash ("sub/", "../", "."): dropping it sent
    // every directory-listing link to "/x/sub", whose own relative links then
    // resolved one level too high
    $last = end($parts);
    $trail = $segments && ($last === '' || $last === '.' || $last === '..');
    return $origin . '/' . implode('/', $segments) . ($trail ? '/' : '') . $suffix;
}
