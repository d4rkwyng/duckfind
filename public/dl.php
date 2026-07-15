<?php
// DuckFind download proxy — fetch a file over modern TLS and stream it to a
// vintage browser over plain HTTP, so old machines can grab software, drivers,
// and archives from HTTPS-only hosts they can't reach directly. This is the
// #1 concrete gap for the software-preservation crowd (Macintosh Garden, driver
// archives): a period browser can read a page through DuckFind but the download
// link on it points at a raw HTTPS URL it can't open.
//
// The file is STREAMED (never buffered whole) so a 50MB archive doesn't touch
// PHP's memory limit; the fetch is SSRF-validated and IP-pinned exactly like the
// rest of DuckFind, with a size cap and a stalled-transfer abort.
require __DIR__ . '/lib.php';
if (!df_rate('dl')) df_rate_block();

define('DL_MAX_BYTES', (int)df_cfg('dl_max_bytes', 52428800));   // 50 MB default — covers
// essentially all real retro software/archives; larger files (CD/DVD images,
// modern installers) aren't realistic on vintage hardware and just burn bandwidth.

$url = df_input('url');
if ($url !== '' && !preg_match('#^[a-z]+://#i', $url)) $url = 'https://' . $url;

if (!preg_match('#^https?://#i', $url)) {
    header('Content-Type: text/html; charset=iso-8859-1');
    echo page_head(DUCKFIND_NAME . ' - download');
    echo '<form action="/dl.php" method="get"><a href="/"><b>' . DUCKFIND_NAME . '</b></a>&nbsp;&nbsp;'
       . 'Download: <input type="text" name="url" size="30" value="' . e($url) . '">&nbsp;'
       . '<input type="submit" value="Get"></form><hr>';
    echo '<p>Paste a file URL and ' . DUCKFIND_NAME . ' fetches it over modern TLS and hands it '
       . 'to your browser over plain HTTP -- so an old machine can download software and '
       . 'archives from HTTPS-only sites. Download links inside the reader route here '
       . 'automatically.</p>';
    echo '<p><font size="1">Files up to <b>' . (int)(DL_MAX_BYTES / 1048576) . ' MB</b> '
       . '(larger files aren&#39;t practical on vintage hardware).</font></p>';
    echo page_foot();
    exit;
}

// filename for the save dialog: basename of the URL path, sanitised to a safe
// ASCII set (no path separators, quotes, or control chars)
$fname = preg_replace('/[^A-Za-z0-9._-]/', '_', rawurldecode(basename((string)parse_url($url, PHP_URL_PATH))));
if ($fname === '' || $fname === '_') $fname = 'download';

if (!dl_stream($url, $fname)) {
    // nothing was streamed (all hops failed / not found) — headers not yet sent
    header('Content-Type: text/html; charset=iso-8859-1');
    echo page_head(DUCKFIND_NAME . ' - download', true)
       . '<p><b>Could not fetch that file.</b> It may be missing, blocked, too large '
       . '(max ' . (int)(DL_MAX_BYTES / 1000000) . ' MB), or on a private host.</p>'
       . '<p>[<a href="' . e($url) . '">try the original link</a>]</p>' . page_foot();
}

// Follow redirects (each re-validated), then stream the final 2xx body straight
// to the client. Returns true once any bytes were sent. Headers (Content-Type /
// Content-Disposition) are emitted lazily on the first body chunk, so a failure
// before that still leaves us free to render an HTML error page.
function dl_stream(string $url, string $fname): bool {
    if (!function_exists('curl_init')) return false;
    // Hard wall-clock cap on the whole download so a slow ORIGIN can't hold a
    // php-fpm worker for hours (the old CURLOPT_TIMEOUT=0 let one IP drip a 50MB
    // file just above the low-speed floor and pin a worker ~14h). 15 min is
    // ample for a legit small file even to a dial-up client; the low-speed abort
    // still catches an outright stall.
    $deadline = microtime(true) + (int)df_cfg('dl_max_seconds', 900);
    $hops = 0;
    while ($hops++ < 6) {
        if (microtime(true) >= $deadline) return false;
        $t = df_validate_url($url);
        if ($t === null) return false;
        $status = 0; $loc = ''; $ctype = ''; $sent = false; $bytes = 0;
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $t['url'],
            CURLOPT_FOLLOWLOCATION => false,               // follow manually + re-validate
            CURLOPT_CONNECTTIMEOUT => 8,
            CURLOPT_TIMEOUT        => max(1, (int)($deadline - microtime(true))),   // total cap
            CURLOPT_LOW_SPEED_LIMIT => 1024,               // abort an outright stall
            CURLOPT_LOW_SPEED_TIME => 30,
            CURLOPT_USERAGENT      => DUCKFIND_UA,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_PROTOCOLS      => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_RESOLVE        => [$t['host'] . ':' . $t['port'] . ':' . $t['ip']],
            CURLOPT_HEADERFUNCTION => function ($ch, $h) use (&$status, &$loc, &$ctype) {
                if (preg_match('#^HTTP/\S+\s+(\d+)#', $h, $m)) $status = (int)$m[1];
                elseif (stripos($h, 'Location:') === 0)     $loc = trim(substr($h, 9));
                elseif (stripos($h, 'Content-Type:') === 0) $ctype = trim(substr($h, 13));
                return strlen($h);
            },
            CURLOPT_WRITEFUNCTION  => function ($ch, $chunk) use (&$sent, &$status, &$bytes, &$ctype, $fname, $deadline) {
                if ($status >= 300 && $status < 400) return strlen($chunk);   // discard redirect body
                if ($status >= 400 || $status === 0)  return 0;               // abort on error
                if (microtime(true) >= $deadline)     return 0;               // wall-clock cap mid-stream
                if (!$sent) {
                    header('Content-Type: ' . (preg_match('#^[\w.+-]+/[\w.+-]+#', $ctype)
                        ? explode(';', $ctype)[0] : 'application/octet-stream'));
                    header('Content-Disposition: attachment; filename="' . $fname . '"');
                    header('Cache-Control: public, max-age=86400');
                    $sent = true;
                }
                $bytes += strlen($chunk);
                if ($bytes > DL_MAX_BYTES) return 0;                          // cap -> abort
                echo $chunk;
                return strlen($chunk);
            },
        ]);
        curl_exec($ch);
        curl_close($ch);
        if ($status >= 300 && $status < 400 && $loc !== '') { $url = absolutize($t['url'], $loc); continue; }
        return $sent;
    }
    return false;
}
