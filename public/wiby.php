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
// Wiby's pages are 1-based (its own "Find more" goes to p=2), 12 results each.
// The old 0-based default made the first "more results" reload page 1.
$p = max(1, (int)df_str($_GET['p'] ?? '1'));
const WIBY_PER_PAGE = 12;

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
echo '<form action="/wiby.php" method="get">' . df_brand_link() . '&nbsp;&nbsp;'
   . 'Classic web: <input type="text" name="q" size="26" value="' . e($q) . '">&nbsp;'
   . '<input type="submit" value="Quack!"></form><hr>';

if ($q === '') {
    echo '<p>Search the <b>classic web</b> -- hand-made, lightweight pages indexed by '
       . '<a href="/read.php?url=' . urlencode('https://wiby.me/about/') . '">Wiby</a>. '
       . 'These pages usually render beautifully on vintage machines without any help.</p>';
    echo '<p>[<a href="/wiby.php?surprise=1"><b>surprise me</b></a>] -- a random classic page</p>';
    echo page_foot(); exit;
}

$results = wiby_search($q, $p);
if ($results === null) {
    echo '<p><b>Wiby is not answering right now.</b> Please try again in a moment.</p>';
    echo page_foot(); exit;
}

if (!$results) {
    echo '<p>No classic-web results for <b>' . e($q) . '</b>. '
       . '[<a href="/?q=' . urlencode($q) . '">search the whole web instead</a>]</p>';
} else {
    echo '<ol start="' . (($p - 1) * WIBY_PER_PAGE + 1) . '">';
    foreach ($results as $r) {
        // raw=1: these pages are already vintage-friendly — DuckFind just does
        // the TLS handshake and script-stripping, and leaves the layout alone
        // signed (lib.php df_readtok): our own result link, like search results
        echo '<li><a href="/read.php?url=' . urlencode($r['url']) . '&amp;raw=1' . df_readtok_qs($r['url'], true)
           . '"><b>' . e($r['title']) . '</b></a>'
           . ' <font size="1">[<a href="' . e($r['url']) . '">direct</a>]</font><br>'
           . '<font size="1" color="' . df_url_color() . '">' . e(df_shorten($r['url'])) . '</font>';
        if ($r['snippet'] !== '') echo '<br>' . e($r['snippet']);
        echo '<br>&nbsp;</li>';
    }
    echo '</ol>';
    $nav = [];
    if ($p > 1) {
        $nav[] = '<a href="/wiby.php?q=' . urlencode($q) . ($p > 2 ? '&amp;p=' . ($p - 1) : '') . '">&lt; previous</a>';
    }
    if (count($results) >= WIBY_PER_PAGE) {
        $nav[] = '<a href="/wiby.php?q=' . urlencode($q) . '&amp;p=' . ($p + 1) . '">more results &gt;</a>';
    }
    if ($nav) echo '<p>' . implode(' &nbsp;&middot;&nbsp; ', $nav) . '</p>';
}
echo '<p><font size="1">[<a href="/wiby.php?surprise=1">surprise me</a>] &middot; '
   . 'classic-web results by <a href="/read.php?url=' . urlencode('https://wiby.me/about/')
   . '">Wiby</a> &middot; [<a href="/?q=' . urlencode($q) . '">whole-web results</a>]</font></p>';
echo page_foot();

// Wiby's documented JSON endpoint (wiby.me/json/?q=&p=), checked 2026-11-12:
// [{URL, Title, Snippet, Description}], 12 per page. Replaces scraping the HTML
// result page, whose snippet text began with the URL (so it showed twice).
// Returns [['url','title','snippet']] (possibly empty) or null on an outage.
function wiby_search(string $q, int $p): ?array {
    $url = 'https://wiby.me/json/?q=' . urlencode($q) . ($p > 1 ? '&p=' . $p : '');
    // test seam: tests/run.php sets $GLOBALS['DF_TEST_HTTP'] instead of the network
    $res = isset($GLOBALS['DF_TEST_HTTP']) ? ($GLOBALS['DF_TEST_HTTP'])($url) : http_get_cached($url, 600);
    if ($res === null || ($res['status'] ?? 200) >= 400) return null;
    $j = json_decode((string)$res['body'], true);
    if (!is_array($j)) return null;
    return wiby_parse($j);
}
function wiby_parse(array $j): array {
    $out = [];
    foreach ($j as $r) {
        if (!is_array($r)) continue;
        $href = trim((string)($r['URL'] ?? ''));
        if (!preg_match('#^https?://#i', $href)) continue;
        $clean = function ($v): string {
            return trim(preg_replace('/\s+/u', ' ', html_entity_decode(strip_tags((string)$v), ENT_QUOTES | ENT_HTML5, 'UTF-8')) ?? '');
        };
        $title = $clean($r['Title'] ?? '');
        $snip  = $clean(($r['Description'] ?? '') !== '' ? $r['Description'] : ($r['Snippet'] ?? ''));
        if ($title !== '' && stripos($snip, $title) === 0) $snip = trim(substr($snip, strlen($title)));
        if (stripos($snip, $href) === 0) $snip = trim(substr($snip, strlen($href)));
        $out[] = ['url' => $href, 'title' => $title !== '' ? $title : $href, 'snippet' => $snip];
    }
    return $out;
}
