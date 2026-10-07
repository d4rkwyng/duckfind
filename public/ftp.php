<?php
// DuckFind FTP gateway — browse and download from anonymous FTP archives, the
// one real download-source gap dl.php doesn't close: dl.php proxies modern
// HTTPS-only hosts to plain HTTP, but plenty of the software-preservation
// world (vintage driver/freeware archives, university mirrors) is still
// plain anonymous FTP, which many vintage browsers either can't speak at all
// or can't negotiate reliably over a modern network path.
//
// Uses curl's own FTP client (not a hand-rolled raw socket like gopher.php --
// FTP's PASV data-connection handshake is real protocol complexity curl
// already gets right) with the same SSRF discipline as the rest of
// DuckFind: hostname sanity check, every resolved IP must be public, the
// control connection is pinned to the validated IP, and CURLOPT_FTP_SKIP_PASV_IP
// forces the data connection to reuse that same pinned IP too -- without it, a
// malicious server's PASV reply could redirect the data connection to an
// arbitrary internal host:port, a known FTP-proxy SSRF vector. Only the
// standard port 21 is allowed, same reasoning as gopher.php's port-70-only
// restriction: no using this as a public TCP port scanner. Always logs in as
// anonymous -- any userinfo in the given URL is dropped, both because a public
// proxy shouldn't relay third-party FTP credentials and so one never ends up
// sitting in server logs or this app's own rate-limit/cache keys.
//
// A URL ending in "/" (or the bare root) is a directory listing, rendered as
// a link list same style as gopher.php's menu; anything else is treated as a
// file and streamed straight through, same shape as dl.php's dl_stream().
// ftps:// (explicit/implicit TLS) is out of scope for v1 -- the realistic
// audience here is old, unmaintained anonymous-FTP archives, which are
// essentially never TLS-only, same scope call gopher.php made by not
// supporting gophers://.
require __DIR__ . '/lib.php';
if (!df_rate('ftp')) df_rate_block();

define('FTP_LIST_CAP', 1000000);                              // 1 MB listing cap
define('FTP_MAX_BYTES', (int)df_cfg('dl_max_bytes', 52428800));  // same ceiling as dl.php

$url = trim(df_input('url'));
if ($url !== '' && !preg_match('#^[a-z]+://#i', $url)) $url = 'ftp://' . $url;

if (!preg_match('#^ftp://#i', $url)) {
    header('Content-Type: text/html; charset=iso-8859-1');
    echo page_head(DUCKFIND_NAME . ' - ftp');
    echo '<form action="/ftp.php" method="get">' . df_brand_link() . '&nbsp;&nbsp;'
       . 'FTP: <input type="text" name="url" size="34" value="' . e($url) . '">&nbsp;'
       . '<input type="submit" value="Go"></form><hr>';
    echo '<p>Enter an anonymous FTP address above (e.g. <tt>ftp://ftp.gnu.org/gnu/</tt>) '
       . 'to browse a directory, or point straight at a file to download it. Login is '
       . 'always anonymous -- '. DUCKFIND_NAME . ' never sends a username or password you '
       . 'supply in the URL.</p>';
    echo '<p><font size="1">Try: '
       . '<a href="/ftp.php?url=' . urlencode('ftp://ftp.gnu.org/gnu/') . '">ftp.gnu.org/gnu</a> &middot; '
       . '<a href="/ftp.php?url=' . urlencode('ftp://ftp.kernel.org/pub/') . '">ftp.kernel.org/pub</a></font></p>';
    echo '<p><font size="1">Files up to <b>' . (int)(FTP_MAX_BYTES / 1048576) . ' MB</b>.</font></p>';
    echo page_foot();
    exit;
}

// --- parse ftp://host[:port]/path, drop any userinfo --------------------------
if (!preg_match('#^ftp://(?:[^@/]*@)?([a-z0-9._\-]+)(?::(\d+))?(/.*)?$#is', $url, $m)) {
    ftp_fail('That does not look like an FTP address. Expected <tt>ftp://host/path/</tt>.');
}
$host = strtolower($m[1]);
$port = isset($m[2]) && $m[2] !== '' ? (int)$m[2] : 21;
$path = $m[3] ?? '/';
$path = str_replace(["\r", "\n", "\t"], '', $path);   // protocol injection guard
$isDir = $path === '' || substr($path, -1) === '/';
$cleanUrl = 'ftp://' . $host . ($port !== 21 ? ':' . $port : '') . $path;

if ($port !== 21) ftp_fail('Only the standard FTP port 21 is supported.');

// From here on this does a real outbound fetch -- gate it (see lib.php).
df_require_browser_proof();

// --- SSRF validation + IP pin, mirrors df_validate_url/gopher.php -------------
$ips = [];
if (filter_var($host, FILTER_VALIDATE_IP)) {
    $ips = [$host];
} else {
    foreach (@dns_get_record($host, DNS_A | DNS_AAAA) ?: [] as $rec) {
        if (!empty($rec['ip']))   $ips[] = $rec['ip'];
        if (!empty($rec['ipv6'])) $ips[] = $rec['ipv6'];
    }
    if (!$ips && ($h = @gethostbynamel($host))) $ips = $h;
}
if (!$ips) ftp_fail('Could not find <b>' . e($host) . '</b>.');
foreach ($ips as $ip) {
    if (!df_ip_is_public($ip)) ftp_fail('That host is not reachable from here.');
}
$ip = $ips[0];

if ($isDir) {
    header('Content-Type: text/html; charset=iso-8859-1');
    echo page_head(DUCKFIND_NAME . ' - ftp: ' . $cleanUrl);
    echo '<form action="/ftp.php" method="get">' . df_brand_link() . '&nbsp;&nbsp;'
       . 'FTP: <input type="text" name="url" size="34" value="' . e($cleanUrl) . '">&nbsp;'
       . '<input type="submit" value="Go"></form><hr>';

    $listing = ftp_list($cleanUrl, $host, $port, $ip);
    if ($listing === null) {
        echo '<p><b>Could not list that directory.</b> It may not exist, or the server '
           . 'refused the connection.</p>' . page_foot();
        exit;
    }

    $parent = ftp_parent_url($cleanUrl);
    echo "<p>\n";
    if ($parent !== null) {
        echo '[DIR] <a href="/ftp.php?url=' . urlencode($parent) . '">.. (up)</a><br>' . "\n";
    }
    foreach (ftp_parse_listing($listing) as $ent) {
        $entUrl = $cleanUrl . rawurlencode($ent['name']) . ($ent['type'] === 'd' ? '/' : '');
        if ($ent['type'] === 'd') {
            echo '[DIR] <a href="/ftp.php?url=' . urlencode($entUrl) . '">' . e($ent['name']) . '</a><br>' . "\n";
        } elseif ($ent['type'] === 'f') {
            echo '[FILE] <a href="/ftp.php?url=' . urlencode($entUrl) . '">' . e($ent['name']) . '</a> '
               . '<font size="1" color="' . df_muted_color() . '">(' . df_shorten_bytes($ent['size']) . ')</font><br>' . "\n";
        } else {
            echo '<font color="' . df_muted_color() . '">' . e($ent['raw']) . '</font><br>' . "\n";
        }
    }
    echo "</p>\n";
    echo '<p><font size="1">ftp gateway &middot; <tt>' . e($cleanUrl) . '</tt></font></p>';
    echo page_foot();
    exit;
}

// --- file: stream straight through, same shape as dl.php's dl_stream() -------
$fname = preg_replace('/[^A-Za-z0-9._-]/', '_', rawurldecode(basename($path)));
if ($fname === '' || $fname === '_') $fname = 'download';

if (!ftp_stream($cleanUrl, $host, $port, $ip, $fname)) {
    header('Content-Type: text/html; charset=iso-8859-1');
    echo page_head(DUCKFIND_NAME . ' - ftp', true)
       . '<p><b>Could not fetch that file.</b> It may be missing, blocked, too large '
       . '(max ' . (int)(FTP_MAX_BYTES / 1000000) . ' MB), or the directory listing above '
       . 'was mistaken for a file.</p>'
       . '<p>[<a href="' . e($cleanUrl) . '">try again</a>]</p>' . page_foot();
}
exit;

// Anonymous login, data connection pinned to the same IP as control (see the
// file-level comment for why CURLOPT_FTP_SKIP_PASV_IP matters).
function ftp_curl_opts(string $url, string $host, int $port, string $ip): array {
    return [
        CURLOPT_URL             => $url,
        CURLOPT_PROTOCOLS       => CURLPROTO_FTP,
        CURLOPT_USERPWD         => 'anonymous:guest@duckfind',
        CURLOPT_FTP_SKIP_PASV_IP => true,
        CURLOPT_CONNECTTIMEOUT  => 8,
        CURLOPT_RESOLVE         => [$host . ':' . $port . ':' . $ip],
    ];
}

function ftp_list(string $url, string $host, int $port, string $ip): ?string {
    if (!function_exists('curl_init')) return null;
    $buf = '';
    $ch = curl_init();
    curl_setopt_array($ch, ftp_curl_opts($url, $host, $port, $ip) + [
        CURLOPT_TIMEOUT        => 15,
        CURLOPT_WRITEFUNCTION  => function ($ch, $chunk) use (&$buf) {
            $buf .= $chunk;
            return strlen($buf) > FTP_LIST_CAP ? 0 : strlen($chunk);
        },
    ]);
    $ok = curl_exec($ch);
    $errno = curl_errno($ch);
    curl_close($ch);
    if ($ok === false && $errno !== CURLE_WRITE_ERROR) return null;
    return $buf;
}

function ftp_stream(string $url, string $host, int $port, string $ip, string $fname): bool {
    if (!function_exists('curl_init')) return false;
    $deadline = microtime(true) + (int)df_cfg('dl_max_seconds', 900);
    $sent = false; $bytes = 0;
    $ch = curl_init();
    curl_setopt_array($ch, ftp_curl_opts($url, $host, $port, $ip) + [
        CURLOPT_TIMEOUT         => max(1, (int)($deadline - microtime(true))),
        CURLOPT_LOW_SPEED_LIMIT => 1024,
        CURLOPT_LOW_SPEED_TIME  => 30,
        CURLOPT_WRITEFUNCTION   => function ($ch, $chunk) use (&$sent, &$bytes, $fname, $deadline) {
            if (microtime(true) >= $deadline) return 0;
            if (!$sent) {
                header('Content-Type: application/octet-stream');
                header('Content-Disposition: attachment; filename="' . $fname . '"');
                header('Cache-Control: public, max-age=86400');
                $sent = true;
            }
            $bytes += strlen($chunk);
            if ($bytes > FTP_MAX_BYTES) return 0;
            echo $chunk;
            return strlen($chunk);
        },
    ]);
    curl_exec($ch);
    curl_close($ch);
    return $sent;
}

// name/size/type for each real entry; odd lines (totals, unparseable formats)
// come back with type 'raw' so the caller can still show something instead of
// silently dropping the line.
function ftp_parse_listing(string $body): array {
    $out = [];
    foreach (explode("\n", $body) as $line) {
        $line = rtrim($line, "\r");
        if ($line === '' || stripos($line, 'total ') === 0) continue;
        // Unix `ls -l` style: perms links owner group size mon day (year|time) name
        if (preg_match('#^([\-dl])[rwxstST\-]{9}\+?\s+\d+\s+\S+\s+\S+\s+(\d+)\s+\w+\s+\d{1,2}\s+(?:\d{4}|\d{1,2}:\d{2})\s+(.+)$#', $line, $mm)) {
            $name = $mm[3];
            if ($mm[1] === 'l' && ($p = strpos($name, ' -> ')) !== false) $name = substr($name, 0, $p);
            if ($name === '.' || $name === '..') continue;
            $out[] = ['type' => $mm[1] === 'd' ? 'd' : 'f', 'size' => (int)$mm[2], 'name' => $name, 'raw' => $line];
            continue;
        }
        // DOS/Windows FTP style: mm-dd-yy  hh:mmAM/PM  <DIR>|size  name
        if (preg_match('#^\d{2}-\d{2}-\d{2,4}\s+\d{2}:\d{2}(?:AM|PM)?\s+(<DIR>|\d+)\s+(.+)$#i', $line, $mm)) {
            $name = $mm[2];
            if ($name === '.' || $name === '..') continue;
            $out[] = ['type' => strtoupper($mm[1]) === '<DIR>' ? 'd' : 'f',
                       'size' => ctype_digit($mm[1]) ? (int)$mm[1] : 0, 'name' => $name, 'raw' => $line];
            continue;
        }
        $out[] = ['type' => 'raw', 'size' => 0, 'name' => '', 'raw' => $line];
    }
    return $out;
}

// One level up from a directory URL, or null once at the root (nothing above
// "ftp://host/" to go up to). $url always ends in "/" here (isDir); "ftp://"
// itself is exactly 6 chars, so a last-slash index below that means there's
// nothing left above the host root.
function ftp_parent_url(string $url): ?string {
    $trimmed = substr($url, 0, -1);
    $slash = strrpos($trimmed, '/');
    if ($slash === false || $slash < 6) return null;
    return substr($trimmed, 0, $slash + 1);
}

function df_shorten_bytes(int $b): string {
    if ($b >= 1073741824) return round($b / 1073741824, 1) . ' GB';
    if ($b >= 1048576)    return round($b / 1048576, 1) . ' MB';
    if ($b >= 1024)       return round($b / 1024, 1) . ' KB';
    return $b . ' B';
}

function ftp_fail(string $msg): void {
    header('Content-Type: text/html; charset=iso-8859-1');
    echo page_head(DUCKFIND_NAME . ' - ftp', true) . '<p>' . $msg . '</p>' . page_foot();
    exit;
}
