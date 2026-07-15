<?php
// DuckFind gopher gateway — browse gopherspace from any web browser. Gopher
// (RFC 1436) predates the web and is plain text over TCP port 70, which makes
// it a natural fit for HTML 3.2 output: menus become link lists, text files
// become <pre>, search servers become a form.
//
// Fetching is a raw socket (curl's gopher support is disabled site-wide by
// CURLOPT_PROTOCOLS), so this file does its own SSRF discipline mirroring
// df_validate_url: hostname sanity check, every resolved IP must be public,
// the connection is pinned to the validated IP, and ONLY port 70 is allowed —
// no probing arbitrary ports through the proxy.
require __DIR__ . '/lib.php';

if (!df_rate('read')) df_rate_block();
header('Content-Type: text/html; charset=iso-8859-1');

define('GOPHER_CAP', 1000000);   // 1 MB per fetch
define('GOPHER_TIMEOUT', 10);

$url   = trim(df_input('url'));
$query = df_input('q');

echo page_head(DUCKFIND_NAME . ' - gopher' . ($url !== '' ? ': ' . $url : ''));
echo '<form action="/gopher.php" method="get"><a href="/"><b>' . DUCKFIND_NAME . '</b></a>&nbsp;&nbsp;'
   . 'Gopher: <input type="text" name="url" size="34" value="' . e($url) . '">&nbsp;'
   . '<input type="submit" value="Go"></form><hr>';

if ($url === '') {
    echo '<p>Enter a gopher address above (e.g. <tt>gopher://gopher.floodgap.com/</tt>) '
       . 'to browse gopherspace &mdash; the internet&#39;s pre-web menu system, still '
       . 'alive and perfectly suited to vintage machines.</p>';
    echo '<p><font size="1">Try: '
       . '<a href="/gopher.php?url=' . urlencode('gopher://gopher.floodgap.com/') . '">Floodgap</a> &middot; '
       . '<a href="/gopher.php?url=' . urlencode('gopher://gopher.floodgap.com/7/v2/vs') . '">Veronica-2 search</a> &middot; '
       . '<a href="/gopher.php?url=' . urlencode('gopher://sdf.org/') . '">SDF</a></font></p>';
    echo page_foot(); exit;
}

// --- parse gopher://host[:port]/[type][selector] -----------------------------
if (!preg_match('#^gopher://([a-z0-9._\-]+)(?::(\d+))?(?:/(.*))?$#is', $url, $m)) {
    gopher_fail('That does not look like a gopher address. Expected '
              . '<tt>gopher://host/</tt>.');
}
$host = strtolower($m[1]);
$port = isset($m[2]) && $m[2] !== '' ? (int)$m[2] : 70;
$path = $m[3] ?? '';
$type = $path === '' ? '1' : $path[0];
$sel  = rawurldecode(substr($path, 1) ?: '');
$sel  = str_replace(["\r", "\n", "\t"], '', $sel);      // protocol injection guard

if ($port !== 70) gopher_fail('Only the standard gopher port 70 is supported.');

// --- search servers get a form before we fetch --------------------------------
if ($type === '7' && $query === '') {
    echo '<p><b>This is a gopher search server.</b></p>';
    echo '<form action="/gopher.php" method="get">'
       . '<input type="hidden" name="url" value="' . e($url) . '">'
       . 'Search for: <input type="text" name="q" size="24">&nbsp;'
       . '<input type="submit" value="Go"></form>';
    echo page_foot(); exit;
}

// --- validate + fetch ---------------------------------------------------------
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
if (!$ips) gopher_fail('Could not find <b>' . e($host) . '</b>.');
foreach ($ips as $ip) {
    if (!df_ip_is_public($ip)) gopher_fail('That host is not reachable from here.');
}

$ip   = $ips[0];
$dest = (strpos($ip, ':') !== false ? '[' . $ip . ']' : $ip);   // bracket IPv6
$fp   = @stream_socket_client('tcp://' . $dest . ':70', $errno, $errstr, GOPHER_TIMEOUT);
if ($fp === false) gopher_fail('Could not connect to <b>' . e($host) . '</b>.');
stream_set_timeout($fp, GOPHER_TIMEOUT);
fwrite($fp, $sel . ($type === '7' ? "\t" . $query : '') . "\r\n");
$body = '';
while (!feof($fp) && strlen($body) < GOPHER_CAP) {
    $chunk = fread($fp, 8192);
    if ($chunk === false || $chunk === '') break;   // eof, error, or timeout
    $body .= $chunk;
}
fclose($fp);
if (strlen($body) >= GOPHER_CAP) $body = substr($body, 0, GOPHER_CAP);

// --- render --------------------------------------------------------------------
if ($type === '0') {
    echo '<pre>' . gopher_e($body) . '</pre>';
} else {
    // menu: one item per line, TYPE+DISPLAY \t SELECTOR \t HOST \t PORT
    echo "<p>\n";
    foreach (explode("\n", $body) as $line) {
        $line = rtrim($line, "\r");
        if ($line === '' || $line === '.') continue;
        $f = explode("\t", $line);
        $it   = $f[0][0] ?? 'i';
        $disp = substr($f[0], 1);
        $isel = $f[1] ?? '';
        $ihost = strtolower(trim($f[2] ?? ''));
        $iport = (int)($f[3] ?? 70);
        $text = gopher_e($disp);
        if ($it === 'i' || $it === '3') {                        // info / error text
            echo ($it === '3' ? '<font color="#AA0000">' . $text . '</font>' : $text) . "<br>\n";
            continue;
        }
        if ($it === 'h' && preg_match('#^URL:(https?://\S+)#i', $isel, $u)) {
            echo '[WWW] <a href="/read.php?url=' . urlencode($u[1]) . '">' . $text . '</a><br>' . "\n";
            continue;
        }
        if (!in_array($it, ['0', '1', '7'], true) || $ihost === '' || $iport !== 70) {
            // binaries, telnet, CSO, odd ports: show but don't link
            echo '<font color="' . df_muted_color() . '">[' . e($it) . '] ' . $text . '</font><br>' . "\n";
            continue;
        }
        $gurl = 'gopher://' . $ihost . '/' . $it . str_replace('%2F', '/', rawurlencode($isel));
        $tag  = $it === '1' ? '[DIR]' : ($it === '7' ? '[?]' : '[TXT]');
        echo $tag . ' <a href="/gopher.php?url=' . urlencode($gurl) . '">' . $text . '</a><br>' . "\n";
    }
    echo "</p>\n";
}
echo '<p><font size="1">gopher gateway &middot; <tt>' . e($url) . '</tt></font></p>';
echo page_foot();

// Gopher content is usually ASCII/latin-1, sometimes UTF-8 — normalise so the
// entity encoder never chokes on it.
function gopher_e(string $s): string {
    if (!mb_check_encoding($s, 'UTF-8')) $s = mb_convert_encoding($s, 'UTF-8', 'ISO-8859-1');
    return e($s);
}

function gopher_fail(string $msg): void {
    echo '<p>' . $msg . '</p>' . page_foot();
    exit;
}
