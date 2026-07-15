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

function df_input(string $key): string {
    if (isset($_GET[$key])) return trim((string)$_GET[$key]);
    if (PHP_SAPI === 'cli' && isset($GLOBALS['argv'][1])) return trim((string)$GLOBALS['argv'][1]);
    return '';
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
    foreach (['100.64.0.0/10', '192.0.0.0/24', '198.18.0.0/15',
              '::ffff:0:0/96', '64:ff9b::/96', '2001:db8::/32'] as $cidr) {
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
    $host = $p['host'];
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
function http_get(string $url, int $maxlen = 3000000): ?array {
    $hops = 0;
    while ($hops++ < 6) {
        $t = df_validate_url($url);
        if ($t === null) return null;
        $r = df_fetch_once($t, $maxlen);
        if ($r === null) return null;
        if ($r['status'] >= 300 && $r['status'] < 400 && $r['location'] !== '') {
            $url = absolutize($t['url'], $r['location']);
            continue;
        }
        return ['body' => $r['body'], 'ctype' => $r['ctype']];
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
        CURLOPT_TIMEOUT        => DUCKFIND_TIMEOUT,
        CURLOPT_CONNECTTIMEOUT => 8,
        CURLOPT_USERAGENT      => DUCKFIND_UA,
        CURLOPT_HTTPHEADER     => ['Accept: text/html,*/*', 'Accept-Language: en-US,en'],
        CURLOPT_ENCODING       => '',                    // gzip/deflate/br
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_PROTOCOLS      => CURLPROTO_HTTP | CURLPROTO_HTTPS,   // no file://, gopher://, ...
        CURLOPT_RESOLVE        => [$t['host'] . ':' . $t['port'] . ':' . $t['ip']],   // pin IP
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
    curl_close($ch);
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

function df_cache_put(string $key, string $data): void {
    $f = df_cache_path($key);
    $sub = dirname($f);
    if (!is_dir($sub)) @mkdir($sub, 0777, true);
    @file_put_contents($f, $data, LOCK_EX);
    df_cache_gc();
}

// Occasionally evict cache entries older than the longest TTL so the cache
// can't grow without bound — no cron required. Runs on ~0.5% of writes.
function df_cache_gc(): void {
    if (function_exists('random_int')) { try { if (random_int(1, 200) !== 1) return; } catch (\Throwable $e) { return; } }
    elseif (mt_rand(1, 200) !== 1) return;
    $dir = (string)df_cfg('cache_dir', sys_get_temp_dir() . '/duckfind-cache');
    $cutoff = time() - 7 * 86400;
    foreach (glob($dir . '/*/*') ?: [] as $f) {
        if (@filemtime($f) < $cutoff) @unlink($f);
    }
}

// Cached wrapper around http_get (raw page bytes + content-type).
function http_get_cached(string $url, int $ttl, int $maxlen = 3000000): ?array {
    $key = 'raw:' . $url;
    if ($ttl > 0 && ($c = df_cache_get($key, $ttl)) !== null) {
        $d = @unserialize($c);
        if (is_array($d)) return $d;
    }
    $r = http_get($url, $maxlen);
    if ($r !== null && $ttl > 0) df_cache_put($key, serialize($r));
    return $r;
}

// Fetch an archived snapshot (web.archive.org "id_" raw bytes), trying HTTPS then
// HTTP. The Internet Archive rate-limits per-endpoint under load, so if one port
// is throttled the other usually still answers. Cached by (timestamp, url) so a
// hit skips the network entirely regardless of which scheme succeeded.
function df_wayback_get(string $ts, string $url, int $ttl = 86400, int $maxlen = 3000000): ?array {
    $key = 'wb:' . $ts . ':' . $url;
    if (($c = df_cache_get($key, $ttl)) !== null) {
        $d = @unserialize($c);
        if (is_array($d)) return $d;
    }
    foreach (['https', 'http'] as $scheme) {
        $r = http_get($scheme . '://web.archive.org/web/' . $ts . 'id_/' . $url, $maxlen);
        if ($r !== null) { df_cache_put($key, serialize($r)); return $r; }
    }
    return null;
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
    $conv = @mb_convert_encoding($html, 'UTF-8', $cs);
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
    $trusted = false;
    foreach (df_cfg('trusted_proxies', []) as $cidr) {
        if (df_ip_in_cidr($remote, strpos($cidr, '/') !== false ? $cidr : $cidr . '/32')) {
            $trusted = true; break;
        }
    }
    if ($trusted) {
        foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR'] as $k) {
            if (!empty($_SERVER[$k])) {
                $ip = trim(explode(',', $_SERVER[$k])[0]);
                if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
            }
        }
    }
    return filter_var($remote, FILTER_VALIDATE_IP) ? $remote : '0.0.0.0';
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
function df_rate_ok(string $bucket, int $limit, int $window): bool {
    if (PHP_SAPI === 'cli') return true;
    $dir = sys_get_temp_dir() . '/duckfind-rl';
    if (!is_dir($dir)) @mkdir($dir, 0700, true);
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
    if ($ok) {
        $hits[] = $now;
        ftruncate($fp, 0); rewind($fp);
        fwrite($fp, implode(',', $hits));
    }
    fflush($fp); flock($fp, LOCK_UN); fclose($fp);
    df_rl_gc($dir);
    return $ok;
}

// Convenience: apply the configured [limit, window] for a named bucket.
function df_rate(string $bucket): bool {
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
    $dir = sys_get_temp_dir() . '/duckfind-rl';
    if (!is_dir($dir)) @mkdir($dir, 0700, true);
    return $dir . '/daily_' . preg_replace('/[^a-z0-9]/i', '', $bucket) . '_' . gmdate('Ymd');
}
function df_daily_count(string $bucket): int {
    $c = @file_get_contents(df_daily_file($bucket));
    return $c === false ? 0 : (int)$c;
}
function df_daily_inc(string $bucket): void {
    $fp = @fopen(df_daily_file($bucket), 'c+');
    if ($fp === false) return;
    if (flock($fp, LOCK_EX)) {
        $n = (int)stream_get_contents($fp);
        ftruncate($fp, 0); rewind($fp); fwrite($fp, (string)($n + 1));
        fflush($fp); flock($fp, LOCK_UN);
    }
    fclose($fp);
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

// entity-encode a plain string for safe ancient-browser output (result is ASCII)
function e(string $s): string {
    $s = htmlspecialchars(df_translit($s), ENT_QUOTES, 'UTF-8');
    return mb_encode_numericentity($s, [0x80, 0x10FFFF, 0, 0x10FFFF], 'UTF-8');
}

// numeric-entity all non-ASCII chars in a string that already contains HTML tags
function ascii_html(string $html): string {
    return mb_encode_numericentity(df_translit($html), [0x80, 0x10FFFF, 0, 0x10FFFF], 'UTF-8');
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

function page_head(string $title, bool $noindex = false): string {
    $t = e($title);
    $robots = $noindex ? "<meta name=\"robots\" content=\"noindex,nofollow\">\n" : '';
    return "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">\n"
         . "<html><head><title>$t</title>\n"
         . "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=iso-8859-1\">\n"
         . "<link rel=\"shortcut icon\" href=\"/favicon.gif?v=4\" type=\"image/gif\">\n"
         . $robots
         // theme comes from the cookie; on vintage browsers dark mode is just the
         // classic <body> colour attributes (HTML 3.2, works everywhere)
         . "</head><body " . df_body_colors() . ">\n"
         // constrain content to a comfortable reading width, centred on the page
         // (text stays left-aligned within it); harmless on narrow vintage screens
         . "<table width=\"760\" align=\"center\" border=\"0\" cellpadding=\"8\" cellspacing=\"0\"><tr><td>\n";
}

function page_foot(): string {
    // The no-logs claim is only honest if the whole host cooperates (no access
    // logs, no logging proxy in front), so it stays off unless the operator
    // affirms it in config (see privacy_claims in config.example.php).
    $privacy = df_cfg('privacy_claims', false)
        ? "<br>no ads &middot; no tracking &middot; no logging"
        : "";
    return "\n<hr>\n<p><font size=\"1\"><a href=\"/\">" . DUCKFIND_NAME . "</a> &middot; "
         . "<a href=\"/settings.php\">settings</a> &middot; "
         . "<a href=\"/about.php\">about</a> &middot; "
         . "a retro-friendly web search &amp; reader, served in plain HTML for vintage browsers<br>"
         . "inspired by <a href=\"http://frogfind.com/\">FrogFind</a> &middot; "
         . "search powered by <a href=\"https://duckduckgo.com/\">DuckDuckGo</a>" . $privacy . "</font></p>\n"
         . "</td></tr></table>\n</body></html>";
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
    if ($rel[0] === '#' || $rel[0] === '?') return $p['scheme'].'://'.$p['host'].$port.$path.$rel;
    $abspath = ($rel[0] === '/') ? $rel : preg_replace('#/[^/]*$#', '/', $path) . $rel;
    $segments = [];
    foreach (explode('/', $abspath) as $seg) {
        if ($seg === '..') array_pop($segments);
        elseif ($seg !== '.' && $seg !== '') $segments[] = $seg;
    }
    return $p['scheme'].'://'.$p['host'].$port.'/'.implode('/', $segments);
}
