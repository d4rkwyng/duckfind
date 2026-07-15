<?php
// DuckFind × Wiby — search the classic web. Wiby (wiby.me) indexes only
// lightweight, hand-made HTML pages, submitted by people rather than crawled
// at scale: the corner of the internet vintage machines were built for.
// Results render in DuckFind's usual plain-HTML list; the "surprise me" mode
// proxies Wiby's beloved random-page button through the reader.
require __DIR__ . '/lib.php';

if (!df_rate('search')) df_rate_block();
header('Content-Type: text/html; charset=iso-8859-1');

$q = df_input('q');
$p = max(0, (int)($_GET['p'] ?? 0));

// --- surprise me: resolve Wiby's random page, read the target -----------------
// wiby.me/surprise/ answers 200 with a meta-refresh (not an HTTP redirect), so
// pull the destination out of the refresh tag. Never cached — that's the point.
if (isset($_GET['surprise'])) {
    $r = http_get('https://wiby.me/surprise/', 100000);
    $loc = '';
    if ($r !== null && preg_match('/http-equiv=["\']?refresh["\']?[^>]*URL=([^"\'>\s]+)/i',
                                  $r['body'], $m)) {
        $loc = html_entity_decode($m[1]);
    }
    if (preg_match('#^https?://#i', $loc)) {
        // original-layout mode: classic pages were built for old browsers, so
        // pass them through (TLS-bridged, scripts sanitised) rather than
        // gutting them with the reader's extractor
        header('Location: /read.php?url=' . urlencode($loc) . '&raw=1', true, 302);
        exit;
    }
    echo page_head(DUCKFIND_NAME . ' - surprise')
       . '<p>The surprise machine is napping. <a href="/wiby.php?surprise=1">Try again</a>.</p>'
       . page_foot();
    exit;
}

echo page_head(DUCKFIND_NAME . ' - classic web search' . ($q !== '' ? ': ' . $q : ''), true);
echo '<form action="/wiby.php" method="get"><a href="/"><b>' . DUCKFIND_NAME . '</b></a>&nbsp;&nbsp;'
   . 'Classic web: <input type="text" name="q" size="26" value="' . e($q) . '">&nbsp;'
   . '<input type="submit" value="Quack!"></form><hr>';

if ($q === '') {
    echo '<p>Search the <b>classic web</b> -- hand-made, lightweight pages indexed by '
       . '<a href="/read.php?url=' . urlencode('https://wiby.me/about/') . '">Wiby</a>. '
       . 'These pages usually render beautifully on vintage machines without any help.</p>';
    echo '<p>[<a href="/wiby.php?surprise=1"><b>surprise me</b></a>] -- a random classic page</p>';
    echo page_foot(); exit;
}

$res = http_get_cached('https://wiby.me/?q=' . urlencode($q) . ($p > 0 ? '&p=' . $p : ''), 600);
if ($res === null) {
    echo '<p><b>Wiby is not answering right now.</b> Please try again in a moment.</p>';
    echo page_foot(); exit;
}

$dom = new DOMDocument();
@$dom->loadHTML(df_to_utf8($res['body'], $res['ctype']));
$results = [];
foreach ($dom->getElementsByTagName('blockquote') as $bq) {
    $a = $bq->getElementsByTagName('a')->item(0);
    if (!$a) continue;
    $href = trim($a->getAttribute('href'));
    if (!preg_match('#^https?://#i', $href)) continue;
    $title = trim(preg_replace('/\s+/', ' ', $a->textContent));
    $snip  = trim(preg_replace('/\s+/', ' ', $bq->textContent));
    if ($title !== '' && strpos($snip, $title) === 0) $snip = trim(substr($snip, strlen($title)));
    $results[] = ['url' => $href, 'title' => $title !== '' ? $title : $href, 'snippet' => $snip];
}

if (!$results) {
    echo '<p>No classic-web results for <b>' . e($q) . '</b>. '
       . '[<a href="/?q=' . urlencode($q) . '">search the whole web instead</a>]</p>';
} else {
    echo '<ol>';
    foreach ($results as $r) {
        // raw=1: these pages are already vintage-friendly — DuckFind just does
        // the TLS handshake and script-stripping, and leaves the layout alone
        echo '<li><a href="/read.php?url=' . urlencode($r['url']) . '&amp;raw=1"><b>' . e($r['title']) . '</b></a>'
           . ' <font size="1">[<a href="' . e($r['url']) . '">direct</a>]</font><br>'
           . '<font size="1" color="' . df_url_color() . '">' . e(df_shorten($r['url'])) . '</font>';
        if ($r['snippet'] !== '') echo '<br>' . e($r['snippet']);
        echo '<br>&nbsp;</li>';
    }
    echo '</ol>';
    if (count($results) >= 10) {
        echo '<p><a href="/wiby.php?q=' . urlencode($q) . '&amp;p=' . ($p + 1) . '">more results &gt;</a></p>';
    }
}
echo '<p><font size="1">[<a href="/wiby.php?surprise=1">surprise me</a>] &middot; '
   . 'classic-web results by <a href="/read.php?url=' . urlencode('https://wiby.me/about/')
   . '">Wiby</a> &middot; [<a href="/?q=' . urlencode($q) . '">whole-web results</a>]</font></p>';
echo page_foot();
