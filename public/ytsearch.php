<?php
// DuckFind YouTube Search -- the !ytsearch shortcut. !watch plays a video you
// already have a link for; this is the missing discovery step -- search
// YouTube and get a plain-HTML results list to click into !watch from.
// Uses the same trusted transcode relay as !watch (see relay_url/relay_secret
// in config.example.php); off by default alongside it.
require __DIR__ . '/lib.php';
header('Content-Type: text/html; charset=iso-8859-1');

$q = df_input('q');
$relayUrl    = rtrim((string)df_cfg('relay_url', ''), '/');
$relaySecret = trim((string)df_cfg('relay_secret', ''));

echo page_head(DUCKFIND_NAME . ' - watch search', true);
echo '<form action="/ytsearch.php" method="get"><a href="/"><b>' . DUCKFIND_NAME . '</b></a>&nbsp;&nbsp;'
   . '<input type="text" name="q" size="30" value="' . e($q) . '">&nbsp;'
   . '<input type="submit" value="Search"></form><hr>';

if ($relayUrl === '' || $relaySecret === '') {
    echo '<p><b>Video playback is not enabled on this ' . DUCKFIND_NAME . '.</b></p>' . page_foot();
    exit;
}

if ($q === '') {
    echo '<p>Search YouTube and get a plain list back -- click a result to watch it '
       . '(converted for old-machine playback via <tt>!watch</tt>). Try <tt>!ytsearch</tt> '
       . 'in the search box.</p>' . page_foot();
    exit;
}

if (!df_rate('ytsearch')) df_rate_block();

$results = ytsearch_query($relayUrl, $relaySecret, $q);
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
    $vurl = 'https://www.youtube.com/watch?v=' . rawurlencode((string)($r['id'] ?? ''));
    $dur  = (int)($r['duration'] ?? 0);
    $durStr = $dur > 0 ? sprintf('%d:%02d', intdiv($dur, 60), $dur % 60) : '';
    echo '<p><a href="/watch.php?url=' . urlencode($vurl) . '">' . e((string)($r['title'] ?? '(untitled)')) . '</a><br>'
       . '<font size="1" color="' . df_muted_color() . '">'
       . e((string)($r['channel'] ?? '')) . ($durStr !== '' ? ' -- ' . $durStr : '') . '</font></p>';
}
echo page_foot();

// Ask the relay for a lightweight YouTube search (title/duration/channel only,
// no video is fetched). A fixed, trusted backend call, like df_ai_ask.
function ytsearch_query(string $relayUrl, string $secret, string $q): ?array {
    if (!function_exists('curl_init')) return null;
    $ch = curl_init($relayUrl . '/search?q=' . rawurlencode($q) . '&n=10');
    curl_setopt_array($ch, [
        CURLOPT_HTTPHEADER     => ['X-Relay-Secret: ' . $secret],
        CURLOPT_CONNECTTIMEOUT => 8,
        CURLOPT_TIMEOUT        => 20,
        CURLOPT_RETURNTRANSFER => true,
    ]);
    $body = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    if ($body === false || $code !== 200) return null;
    $j = json_decode((string)$body, true);
    return is_array($j) && is_array($j['results'] ?? null) ? $j['results'] : null;
}
