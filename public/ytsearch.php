<?php
// DuckFind YouTube Search -- the !ytsearch shortcut. !watch plays a video you
// already have a link for; this is the missing discovery step -- search
// YouTube and get a plain-HTML results list to click into !watch from.
//
// Runs entirely on THIS host via a local yt-dlp (a lightweight metadata query,
// no video is fetched) -- unlike !watch, it does not touch the transcode
// relay, so search stays available even if that backend is down, and the
// relay stays scoped to transcoding only. Needs yt-dlp installed locally (see
// YTDLP_BIN below); without it the page just says so, like pdf.php without
// poppler.
require __DIR__ . '/lib.php';
header('Content-Type: text/html; charset=iso-8859-1');

const YTDLP_BIN = '/opt/ytdlp-venv/bin/yt-dlp';
const RESULTS_PAGE = 10;   // results per "more" click
const RESULTS_MAX  = 30;   // hard cap -- more than this is just abuse, not browsing

$q = df_input('q');
$n = max(RESULTS_PAGE, min(RESULTS_MAX, (int)($_GET['n'] ?? RESULTS_PAGE)));

echo page_head(DUCKFIND_NAME . ' - watch search', true);
echo '<form action="/ytsearch.php" method="get"><a href="/"><b>' . DUCKFIND_NAME . '</b></a>&nbsp;&nbsp;'
   . '<input type="text" name="q" size="30" value="' . e($q) . '">&nbsp;'
   . '<input type="submit" value="Search"></form><hr>';

if (!is_executable(YTDLP_BIN)) {
    echo '<p><b>Video search is not enabled on this ' . DUCKFIND_NAME . '.</b></p>' . page_foot();
    exit;
}

if ($q === '') {
    echo '<p>Search YouTube and get a plain list back -- click a result to watch it '
       . '(converted for old-machine playback via <tt>!watch</tt>). Try <tt>!ytsearch</tt> '
       . 'in the search box.</p>' . page_foot();
    exit;
}

if (!df_rate('ytsearch')) df_rate_block();

$results = ytsearch_run($q, $n);
if ($results === null) {
    echo '<p><b>Search is unavailable right now.</b> Try again in a moment.</p>' . page_foot();
    exit;
}
if (!$results) {
    echo '<p>No results for <b>' . e($q) . '</b>.</p>' . page_foot();
    exit;
}

echo '<p><b>Results for ' . e($q) . '</b></p>';
foreach ($results as $r) {
    $id   = (string)($r['id'] ?? '');
    $vurl = 'https://www.youtube.com/watch?v=' . rawurlencode($id);
    $dur  = (int)($r['duration'] ?? 0);
    $durStr = $dur > 0 ? sprintf('%d:%02d', intdiv($dur, 60), $dur % 60) : '';
    $views = (int)($r['view_count'] ?? 0);
    $viewsStr = $views > 0 ? number_format($views) . ' views' : '';
    $thumb = 'https://i.ytimg.com/vi/' . rawurlencode($id) . '/mqdefault.jpg';

    echo '<table cellpadding="4" cellspacing="0"><tr>'
       . '<td valign="top"><a href="/watch.php?url=' . urlencode($vurl) . '">'
       . '<img src="/img.php?url=' . urlencode($thumb) . '&amp;w=160" width="160" border="0" alt=""></a></td>'
       . '<td valign="top"><a href="/watch.php?url=' . urlencode($vurl) . '">' . e((string)($r['title'] ?? '(untitled)')) . '</a><br>'
       . '<font size="1" color="' . df_muted_color() . '">'
       . e((string)($r['channel'] ?? ''))
       . ($durStr !== '' ? ' -- ' . $durStr : '')
       . ($viewsStr !== '' ? ' -- ' . $viewsStr : '')
       . '</font></td></tr></table>';
}
if (count($results) >= $n && $n < RESULTS_MAX) {
    echo '<p>[<a href="/ytsearch.php?q=' . urlencode($q) . '&n=' . ($n + RESULTS_PAGE) . '">more results</a>]</p>';
}
echo page_foot();

// Run yt-dlp's flat-playlist search locally and return [{id,title,duration,
// channel,view_count}, ...], or null on failure. --flat-playlist avoids
// per-video extraction (fast, no JS runtime needed) but doesn't carry upload
// date -- that needs a full per-video fetch, ~1-2s each, not worth it for a
// results list.
function ytsearch_run(string $q, int $n): ?array {
    $to = is_executable('/usr/bin/timeout') ? ['/usr/bin/timeout', '20'] : [];
    $cmd = array_merge($to, [YTDLP_BIN, '--flat-playlist', '-j', 'ytsearch' . $n . ':' . $q]);
    $p = @proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    if (!is_resource($p)) return null;
    $out = stream_get_contents($pipes[1]);
    fclose($pipes[1]); fclose($pipes[2]);
    proc_close($p);
    if ($out === false) return null;

    $results = [];
    foreach (explode("\n", trim($out)) as $line) {
        if ($line === '') continue;
        $d = json_decode($line, true);
        if (!is_array($d) || empty($d['id'])) continue;
        $results[] = [
            'id' => $d['id'], 'title' => $d['title'] ?? '', 'duration' => $d['duration'] ?? 0,
            'channel' => $d['channel'] ?? $d['uploader'] ?? '', 'view_count' => $d['view_count'] ?? 0,
        ];
    }
    return $results;
}
