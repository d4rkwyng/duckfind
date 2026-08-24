<?php
// DuckFind Watch -- the !watch shortcut. Old machines can't decode modern
// YouTube video (VP9/AV1 in an MP4 container their QuickTime/Media Player has
// never heard of), so this fetches the video server-side and hands back a
// file a vintage plugin can actually play: Cinepak/AVI, MPEG-1, or an old
// Sorenson FLV. A current browser can't play any of those either (no NPAPI
// plugins, no legacy codecs in <video>), so an h264/mp4 profile covers that
// case too, auto-selected for modern-looking User-Agents. Optional and off by
// default -- it needs a transcode relay (see relay_url / relay_secret in
// config.example.php), which is NOT part of this app; it's a small trusted
// backend you run yourself.
require __DIR__ . '/lib.php';
header('Content-Type: text/html; charset=iso-8859-1');

// vintage-friendly output formats. Keep this list in sync with the relay's
// own profile table -- these are just labels/MIME types for the UI.
const WATCH_PROFILES = [
    'mpeg1'    => ['ext' => 'mpg', 'mime' => 'video/mpeg',     'label' => 'MPEG-1 (.mpg) -- QuickTime, Media Player 3.1+'],
    'cinepak'  => ['ext' => 'avi', 'mime' => 'video/x-msvideo', 'label' => 'Cinepak (.avi) -- QuickTime 3+, System 7/8/9'],
    'sorenson' => ['ext' => 'flv', 'mime' => 'video/x-flv',     'label' => 'Sorenson (.flv) -- old Flash Player 6+'],
    'h264'     => ['ext' => 'mp4', 'mime' => 'video/mp4',      'label' => 'MP4/H.264 -- modern browsers'],
];

// None of the vintage formats play natively in a current browser (no NPAPI
// plugins, no MPEG-1/Cinepak/FLV1 in <video>), so a modern-looking UA gets
// h264 by default -- an explicit ?profile= always overrides this.
function watch_default_profile(): string {
    $ua = (string)($_SERVER['HTTP_USER_AGENT'] ?? '');
    if (preg_match('#Chrome/(\d+)#', $ua, $m) && (int)$m[1] >= 50) return 'h264';
    if (preg_match('#Firefox/(\d+)#', $ua, $m) && (int)$m[1] >= 50) return 'h264';
    if (strpos($ua, 'Edg/') !== false) return 'h264';
    if (preg_match('#AppleWebKit/(\d+)#', $ua, $m) && (int)$m[1] >= 600) return 'h264';
    return 'mpeg1';
}

$url     = df_input('url');
if ($url !== '' && !preg_match('#^[a-z]+://#i', $url)) $url = 'https://' . $url;
$profile = $_GET['profile'] ?? watch_default_profile();
if (!isset(WATCH_PROFILES[$profile])) $profile = 'mpeg1';
$raw     = isset($_GET['dl']);
$check   = isset($_GET['check']);
$backSearch = fn() => '/?q=' . urlencode($url);

function watch_landing(string $msg = '', string $url = ''): void {
    echo page_head(DUCKFIND_NAME . ' - watch');
    echo '<form action="/watch.php" method="get"><a href="/"><b>' . DUCKFIND_NAME . '</b></a>&nbsp;&nbsp;'
       . 'Watch: <input type="text" name="url" size="30" value="' . e($url) . '">&nbsp;'
       . '<input type="submit" value="Go"></form><hr>';
    if ($msg !== '') echo '<p><b>' . $msg . '</b></p>';
    echo '<p>Paste a YouTube link and ' . DUCKFIND_NAME . ' fetches and converts it '
       . 'server-side into a format an old machine can actually play -- no VP9/AV1 '
       . 'decoder required. Try <tt>!watch</tt> in the search box.</p>';
    echo '<p><font size="1">The first request for a video transcodes it (can take a '
       . 'little while for a long video); repeat requests are served from cache.</font></p>';
    echo page_foot();
}

$relayUrl    = rtrim((string)df_cfg('relay_url', ''), '/');
$relaySecret = trim((string)df_cfg('relay_secret', ''));
if ($relayUrl === '' || $relaySecret === '') {
    if ($raw) { http_response_code(503); exit; }
    watch_landing('Video playback is not enabled on this ' . DUCKFIND_NAME . '.', $url);
    exit;
}

if (!preg_match('#^https?://#i', $url)) {
    if ($raw) { http_response_code(400); exit; }
    watch_landing();
    exit;
}
$host = strtolower((string)parse_url($url, PHP_URL_HOST));
if (!in_array($host, ['youtube.com', 'www.youtube.com', 'm.youtube.com', 'youtu.be'], true)) {
    if ($raw) { http_response_code(400); exit; }
    watch_landing('Only youtube.com / youtu.be links are supported.', $url);
    exit;
}

// Lightweight JSON status ping used by the wait page's JS (see below) to
// reload as soon as the video is actually ready, instead of waiting out the
// full meta-refresh interval. Own rate bucket -- it's a cheap check, not a
// transcode-triggering hit like the rest of this page.
if ($check) {
    if (!df_rate('watchcheck')) { http_response_code(429); exit; }
    header('Content-Type: application/json');
    echo json_encode(['status' => watch_queue($relayUrl, $relaySecret, $url, $profile)]);
    exit;
}

if (!df_rate('watch')) df_rate_block();

// php.ini's max_execution_time (30s here) counts wall-clock time blocked on a
// slow client read, not just CPU time -- a big video to a slow connection
// would get silently cut off mid-stream otherwise, which looks exactly like
// "only the first few seconds got through". curl's own timeouts still bound
// this (watch_queue: 15s, watch_stream: 300s).
set_time_limit(0);

$relaySrc = $relayUrl . '/v?url=' . rawurlencode($url) . '&profile=' . rawurlencode($profile);

if ($raw) {
    // Forward the client's Range header (if any) so a plugin that already has
    // the cached file's first bytes can seek instead of re-downloading from
    // scratch. Only meaningful once the video is cached -- a cold request has
    // nothing to seek into yet.
    $range = str_replace(["\r", "\n"], '', (string)($_SERVER['HTTP_RANGE'] ?? ''));
    if (!watch_stream($relaySrc, $relaySecret, WATCH_PROFILES[$profile]['mime'], $range)) {
        http_response_code(502);
        header('Content-Type: text/html; charset=iso-8859-1');
        echo page_head(DUCKFIND_NAME . ' - watch', true)
           . '<p><b>Could not fetch/convert that video right now.</b></p>'
           . '<p>[<a href="' . $backSearch() . '">back to search</a>]</p>' . page_foot();
    }
    exit;
}

// ---- HTML landing: queue the transcode, then either the player or a wait page --
// Some vintage plugins pick a handler by sniffing the URL's file extension
// rather than trusting Content-Type, so give the raw-stream URL a real one
// (PATH_INFO after /watch.php/... routes to this same script via Caddy).
$src = '/watch.php/video.' . WATCH_PROFILES[$profile]['ext']
     . '?url=' . urlencode($url) . '&profile=' . urlencode($profile) . '&dl=1';
$nav = '<form action="/watch.php" method="get"><a href="/"><b>' . DUCKFIND_NAME . '</b></a>&nbsp;&nbsp;'
     . '<input type="text" name="url" size="30" value="' . e($url) . '">&nbsp;'
     . '<input type="submit" value="Go"></form><hr>';
$state = watch_queue($relayUrl, $relaySecret, $url, $profile);

if ($state !== 'ready') {
    // Old machines have no JS here, so poll the vintage way: a meta-refresh
    // reloads this same URL every few seconds until the relay reports the
    // file is ready. Browsers this old scan the whole document for
    // http-equiv tags, not just <head>, so this still works even though
    // page_head() has already closed the real one. A manual link covers the
    // few browsers (some text browsers) that ignore the refresh tag.
    echo page_head(DUCKFIND_NAME . ' - watch: ' . $url, true);
    echo '<meta http-equiv="refresh" content="10;url=/watch.php?url=' . urlencode($url)
       . '&amp;profile=' . urlencode($profile) . '">';
    // Progressive enhancement for JS-capable (modern) browsers: poll faster
    // than the 10s meta-refresh and jump the moment it's ready, instead of
    // waiting out the fallback interval. A browser with no/broken fetch()
    // just never runs this and falls back to the meta-refresh above -- same
    // behavior as before, not a second, different failure mode.
    echo '<script>if (typeof fetch === "function") { (function () {'
       . 'var t = setInterval(function () {'
       . 'fetch(' . json_encode('/watch.php?check=1&url=' . urlencode($url) . '&profile=' . urlencode($profile)) . ')'
       . '.then(function (r) { return r.json(); }).then(function (j) {'
       . 'if (j.status === "ready") { clearInterval(t); location.href = '
       . json_encode('/watch.php?url=' . urlencode($url) . '&profile=' . urlencode($profile)) . '; }'
       . '}).catch(function () {});'
       . '}, 3000); })(); }</script>';
    echo $nav;
    echo '<p><b>Transcoding this video for old-machine playback...</b></p>';
    echo '<p>This page will reload every few seconds and switch to the player once it\'s '
       . 'ready. Long videos can take a couple of minutes the first time; after that '
       . 'it\'s served instantly from cache.</p>';
    echo '<p>[<a href="/watch.php?url=' . urlencode($url) . '&profile=' . urlencode($profile) . '">reload now</a>]</p>';
    echo page_foot();
    exit;
}

echo page_head(DUCKFIND_NAME . ' - watch: ' . $url, true);
echo $nav;
if ($profile === 'h264') {
    echo '<p><video src="' . e($src) . '" width="640" height="360" controls></video></p>';
} else {
    echo '<p><embed src="' . e($src) . '" width="480" height="360" controller="true" autoplay="false" '
       . 'type="' . e(WATCH_PROFILES[$profile]['mime']) . '"></embed></p>';
}
echo '<p>[<a href="' . e($src) . '">download / save this video</a>]</p>';
echo '<form action="/watch.php" method="get"><input type="hidden" name="url" value="' . e($url) . '">'
   . 'Format: <select name="profile">';
foreach (WATCH_PROFILES as $key => $p) {
    $sel = $key === $profile ? ' selected' : '';
    echo '<option value="' . e($key) . '"' . $sel . '>' . e($p['label']) . '</option>';
}
echo '</select> <input type="submit" value="Switch"></form>';
echo '<p><font size="1" color="' . df_muted_color() . '">Video is fetched/converted by a '
   . 'separate server reached over Cloudflare -- unlike the rest of ' . DUCKFIND_NAME
   . ', this path is not guaranteed log-free. See <a href="/about.php">about</a>.</font></p>';
echo page_foot();

// Ask the relay to start (or check on) a transcode job and return its state:
// 'ready' | 'processing' | 'none'. Never blocks on the transcode itself --
// that runs in the relay's own background thread -- so this page load stays
// fast even on a cold request.
function watch_queue(string $relayUrl, string $secret, string $url, string $profile): string {
    if (!function_exists('curl_init')) return 'ready';   // fail open to the old blocking path
    $ch = curl_init($relayUrl . '/queue?url=' . rawurlencode($url) . '&profile=' . rawurlencode($profile));
    curl_setopt_array($ch, [
        CURLOPT_HTTPHEADER     => ['X-Relay-Secret: ' . $secret],
        CURLOPT_CONNECTTIMEOUT => 8,
        CURLOPT_TIMEOUT        => 15,
        CURLOPT_RETURNTRANSFER => true,
    ]);
    $body = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    // Relay unreachable/timed out: fail toward the wait page (safe, self-heals
    // on the next poll) rather than 'ready', which would send the embed
    // straight at /v and risk a multi-minute blocking transcode with zero
    // feedback if the video actually isn't cached yet.
    if ($body === false || $code !== 200) return 'processing';
    $j = json_decode((string)$body, true);
    $s = is_array($j) ? ($j['status'] ?? '') : '';
    return in_array($s, ['ready', 'processing', 'none'], true) ? $s : 'ready';
}

// Stream the relay's response straight through to the client. This is a
// fixed, trusted backend (like df_ai_ask's Anthropic call) -- not the
// SSRF-guarded fetch path, since the relay itself validates and only ever
// talks to youtube.com/youtu.be on our behalf.
function watch_stream(string $src, string $secret, string $mime, string $range = ''): bool {
    if (!function_exists('curl_init')) return false;
    $sent = false; $status = 0; $respHeaders = [];
    $reqHeaders = ['X-Relay-Secret: ' . $secret];
    if ($range !== '') $reqHeaders[] = 'Range: ' . $range;
    $ch = curl_init($src);
    curl_setopt_array($ch, [
        CURLOPT_HTTPHEADER     => $reqHeaders,
        CURLOPT_CONNECTTIMEOUT => 8,
        CURLOPT_TIMEOUT        => 300,   // cold transcode can take a while
        CURLOPT_HEADERFUNCTION => function ($ch, $h) use (&$status, &$respHeaders) {
            if (preg_match('#^HTTP/\S+\s+(\d+)#', $h, $m)) { $status = (int)$m[1]; $respHeaders = []; }
            elseif (preg_match('#^(Content-Range|Content-Length|Accept-Ranges):\s*(.+)$#i', trim($h), $m)) {
                $respHeaders[strtolower($m[1])] = trim($m[2]);
            }
            return strlen($h);
        },
        CURLOPT_WRITEFUNCTION  => function ($ch, $chunk) use (&$sent, $mime, &$status, &$respHeaders) {
            if ($status >= 400 || $status === 0) return 0;
            if (!$sent) {
                http_response_code($status === 206 ? 206 : 200);
                header('Content-Type: ' . $mime);
                header('Cache-Control: public, max-age=86400');
                if (isset($respHeaders['accept-ranges'])) header('Accept-Ranges: ' . $respHeaders['accept-ranges']);
                if ($status === 206 && isset($respHeaders['content-range'])) header('Content-Range: ' . $respHeaders['content-range']);
                if (isset($respHeaders['content-length'])) header('Content-Length: ' . $respHeaders['content-length']);
                $sent = true;
            }
            echo $chunk;
            return strlen($chunk);
        },
    ]);
    curl_exec($ch);
    curl_close($ch);
    return $sent;
}
