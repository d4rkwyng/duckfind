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
function http_get(string $url, int $maxlen = 3000000, string $ua = '', ?string $post = null, int $timeout = 0): ?array {
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
        CURLOPT_HTTPHEADER     => isset($t['post'])
            ? ['Accept: */*', 'Content-Type: text/plain']
            : ['Accept: text/html,*/*', 'Accept-Language: en-US,en'],
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
function http_get_cached(string $url, int $ttl, int $maxlen = 3000000, string $ua = ''): ?array {
    $key = 'raw:' . ($ua !== '' ? sha1($ua) . ':' : '') . $url;
    if ($ttl > 0 && ($c = df_cache_get($key, $ttl)) !== null) {
        $d = @unserialize($c, ['allowed_classes' => false]);
        if (is_array($d)) return $d;
    }
    $r = http_get($url, $maxlen, $ua);
    if ($ttl > 0 && df_cacheable_response($r)) df_cache_put($key, serialize($r));
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
        if (is_array($d)) return $d;
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
            if (df_cacheable_response($r)) df_cache_put($key, serialize($r));
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
function df_require_browser_proof(bool $allowLegacy = true): void {
    if ($allowLegacy ? df_pob_pass() : df_pob_valid(df_str($_COOKIE['df_pob'] ?? ''))) return;

    if (($_GET['_pob'] ?? '') === '1') {
        header('Content-Type: text/html; charset=iso-8859-1');
        echo page_head(DUCKFIND_NAME . ' - cookies required', true)
           . '<h1>Cookies are required for this feature</h1>'
           . '<p>This page needs a short-lived cookie to confirm a real browser is '
           . 'asking, not an automated script. Please enable cookies and try again.</p>'
           . page_foot();
        exit;
    }

    setcookie('df_pob', df_pob_token(), [
        'expires' => time() + 3600, 'path' => '/', 'samesite' => 'Lax', 'httponly' => true,
    ]);
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
    return df_hourly_inc_capped('maptile', (int)df_cfg('map_tile_hourly_cap', 300), $now);
}
function df_ftp_budget_block(): void {
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
    if (preg_match('#^image/#i', (string)$res['ctype'])) {
        $info = @getimagesizefromstring($res['body']);
        if ($info !== false && (int)$info[0] * (int)$info[1] <= 12000000) {
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
    // Resample into a small truecolor canvas that KEEPS alpha (blending off),
    // then composite each cell against the background by hand.
    $t = imagecreatetruecolor($cols, $rows);
    imagealphablending($t, false);
    imagesavealpha($t, true);
    imagefilledrectangle($t, 0, 0, $cols - 1, $rows - 1, imagecolorallocatealpha($t, 0, 0, 0, 127));
    imagecopyresampled($t, $src, 0, 0, 0, 0, $cols, $rows, $sw, $sh);
    $bg = $darkBg ? 0.0 : 255.0;
    $L = [];
    for ($y = 0; $y < $rows; $y++) {
        for ($x = 0; $x < $cols; $x++) {
            $c = imagecolorat($t, $x, $y);
            $a = (($c >> 24) & 0x7F) / 127;                          // 0 opaque .. 1 clear
            $lum = 0.299 * (($c >> 16) & 0xFF) + 0.587 * (($c >> 8) & 0xFF) + 0.114 * ($c & 0xFF);
            $L[] = $lum * (1 - $a) + $bg * $a;                       // composite on page bg
        }
    }
    unset($t);
    // Auto-levels: a photo's tones usually sit in a narrow mid band, which
    // a 10-step ramp turns into a wall of one character. Stretch the 2nd..98th
    // percentile to the full range -- only when there IS real tonal range
    // (>= 48 of 255), so a flat or near-flat image keeps its true density.
    $sorted = $L; sort($sorted);
    $cnt = count($sorted);
    $lo = $sorted[(int)floor(($cnt - 1) * 0.02)];
    $hi = $sorted[(int)ceil(($cnt - 1) * 0.98)];
    $stretch = ($hi - $lo) >= 48;
    $lines = [];
    for ($y = 0, $i = 0; $y < $rows; $y++) {
        $line = '';
        for ($x = 0; $x < $cols; $x++, $i++) {
            $l = $stretch ? ($L[$i] - $lo) * 255 / ($hi - $lo) : $L[$i];
            $d = $darkBg ? $l / 255 : 1 - $l / 255;                  // ink density 0..1
            $line .= $ramp[(int)round(max(0.0, min(1.0, $d)) * ($n - 1))];
        }
        $lines[] = htmlspecialchars(rtrim($line, ' '), ENT_QUOTES, 'ISO-8859-1');
    }
    return implode("\n", $lines);
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
    $ckey = 'ascii:' . DF_ASCII_COLS . ':' . ($dark ? 'd' : 'l') . ':' . $year . ':' . $url;
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
    $pre = '<pre>' . df_ascii_art($img, DF_ASCII_COLS, $dark) . '</pre>';
    unset($img);
    df_cache_put($ckey, $pre);
    $count++;
    return $pre;
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
         . "search powered by <a href=\"https://duckduckgo.com/\">DuckDuckGo</a>" . $privacy . "</font></p>\n"
         . "</font></td></tr></table>\n</body></html>";   // close the base-size font from page_head
}

// Fetch and parse an RSS 2.0 / Atom feed into [title, link, ts] items,
// cached 30 minutes (shared across all users of the same feed). The cache
// always holds up to 15 items regardless of $limit — the key is per-URL, so
// caching a shorter slice would starve later callers that want more.
function df_feed_items(string $url, int $limit): array {
    $limit = min($limit, 15);
    if (($c = df_cache_get('feed2:' . $url, 1800)) !== null) {
        $d = @unserialize($c, ["allowed_classes" => false]);
        if (is_array($d)) return array_slice($d, 0, $limit);
    }
    // short negative cache: this feed failed recently -- don't refetch it on
    // every reload for ~10 min (same idea as img.php's imgfail:). A reader full
    // of dead or slow feed URLs otherwise costs a fresh timeout per feed per load.
    if (df_cache_get('feedfail:' . $url, 600) !== null) return [];
    $want  = $limit;
    $limit = 15;
    $out = [];
    $ok  = false;
    $r = http_get($url, 2000000);
    if ($r !== null) {
        $xml = @simplexml_load_string($r['body'], 'SimpleXMLElement', LIBXML_NOCDATA | LIBXML_NONET);
        if ($xml !== false) {
            $ok = true;
            if (isset($xml->channel->item)) {                 // RSS 2.0
                foreach ($xml->channel->item as $it) {
                    $desc = (string)$it->description;
                    // full HTML often lives in content:encoded, not description
                    $cenc = (string)$it->children('http://purl.org/rss/1.0/modules/content/')->encoded;
                    $out[] = [
                        'title' => df_feed_title((string)$it->title),
                        'link'  => trim((string)$it->link),
                        'ts'    => strtotime((string)$it->pubDate) ?: 0,
                        'desc'  => df_feed_text($desc !== '' ? $desc : $cenc),
                        'img'   => df_feed_img($it, $cenc . ' ' . $desc),
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
                              'ts' => strtotime($when) ?: 0,
                              'desc' => df_feed_text($sum !== '' ? $sum : $con),
                              'img'  => df_feed_img($en, $con . ' ' . $sum)];
                    if (count($out) >= $limit) break;
                }
            }
        }
    }
    $out = array_values(array_filter($out,
        fn($i) => $i['title'] !== '' && preg_match('#^https?://#i', $i['link'])));
    if ($ok) df_cache_put('feed2:' . $url, serialize($out));   // don't cache transient failures...
    else     df_cache_put('feedfail:' . $url, '1');            // ...beyond the 10-min negative entry
    return array_slice($out, 0, $want);
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

    $o = '<table border="0" cellpadding="3" cellspacing="0" width="100%">';
    foreach ($items as $it) {
        $ru = '/read.php?url=' . htmlspecialchars(urlencode($it['link']), ENT_QUOTES);
        $o .= '<tr>';
        if ($col) {
            $o .= '<td width="96" valign="top">';
            if (($it['img'] ?? '') !== '') {
                $o .= '<a href="' . $ru . '"><img src="/img.php?url='
                    . htmlspecialchars(urlencode($it['img']), ENT_QUOTES) . '&amp;w=88' . $imMode
                    . '" border="0" alt="*"></a>';
            }
            $o .= '</td>';
        }
        $o .= '<td valign="top"><a href="' . $ru . '"><b>' . e((string)$it['title']) . '</b></a>'
            . ' <font size="1" color="' . df_muted_color() . '">- ' . e((string)($it['src'] ?? ''))
            . (!empty($it['ts']) ? ', ' . gmdate('M j', (int)$it['ts']) : '') . '</font>';
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
