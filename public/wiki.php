<?php
// DuckFind Wikipedia lookup — a dedicated, clean encyclopedia page, same
// family as define.php (dictionaryapi.dev) and wiby.php (own result format)
// rather than routing wiki pages through read.php's general-purpose
// readability extractor, which is built to fight news-site clutter (ads,
// nav chrome, cookie banners) and isn't tuned for MediaWiki's own markup.
// Wikipedia's REST summary endpoint gives a short, clean lead extract with
// no infoboxes/citations/templates to strip; "read the full article" still
// goes through read.php, reusing its existing extractor rather than
// building a second long-form reader for one site.
require __DIR__ . '/lib.php';
if (!df_rate('search')) df_rate_block();
header('Content-Type: text/html; charset=iso-8859-1');

define('WIKI_UA', DUCKFIND_UA);

$q = trim(df_input('q'));

echo page_head(DUCKFIND_NAME . ' - wiki' . ($q !== '' ? ': ' . $q : ''));
echo '<form action="/wiki.php" method="get">' . df_brand_link() . '&nbsp;&nbsp;'
   . 'Wikipedia: <input type="text" name="q" size="24" value="' . e($q) . '">&nbsp;'
   . '<input type="submit" value="Look up"></form><hr>';

if ($q === '') {
    echo '<p>Look up a Wikipedia article and read a clean summary -- no infoboxes, '
       . 'citations, or clutter. Try <tt>!wiki</tt> in the search box.</p>' . page_foot();
    exit;
}

$summary = wiki_summary($q);
// A title that doesn't match exactly (typos, lowercase, a partial phrase)
// 404s the direct summary lookup -- opensearch resolves it to the nearest
// real article title, same forgiving-match spirit as a normal search box,
// before giving up entirely.
if ($summary === null) {
    $resolved = wiki_resolve($q);
    if ($resolved !== null && $resolved !== $q) $summary = wiki_summary($resolved);
}

if ($summary === null) {
    echo '<p>No Wikipedia article found for <b>' . e($q) . '</b>. '
       . '[<a href="/?q=' . e(urlencode($q)) . '">search instead</a>]</p>' . page_foot();
    exit;
}

$title = (string)($summary['title'] ?? $q);
$pageUrl = (string)($summary['content_urls']['desktop']['page'] ?? '');
$readerUrl = $pageUrl !== '' ? '/read.php?url=' . urlencode($pageUrl) : '';

echo '<h2>' . e($title) . '</h2>';

if (($summary['type'] ?? '') === 'disambiguation') {
    echo '<p><b>' . e($title) . '</b> could mean more than one thing. '
       . ($readerUrl !== '' ? '<a href="' . e($readerUrl) . '">See the disambiguation page</a> to pick one.'
                             : 'Try a more specific search.') . '</p>';
    echo page_foot();
    exit;
}

if (!empty($summary['thumbnail']['source'])) {
    echo '<img src="/img.php?url=' . urlencode((string)$summary['thumbnail']['source']) . '&amp;w=200" '
       . 'width="200" align="right" hspace="12" vspace="4" alt="">';
}
if (!empty($summary['description'])) {
    echo '<p><font size="1" color="' . df_muted_color() . '"><i>' . e((string)$summary['description'])
       . '</i></font></p>';
}
echo '<p>' . nl2br(e((string)($summary['extract'] ?? '')), false) . '</p>';
echo '<br clear="right">';
if ($readerUrl !== '') {
    echo '<p>[<a href="' . e($readerUrl) . '">read the full article</a>]</p>';
}
echo '<p><font size="1">Source: <a href="' . e($pageUrl !== '' ? $pageUrl : 'https://www.wikipedia.org/')
   . '">Wikipedia</a>, CC BY-SA</font></p>';
echo page_foot();

// Fetch the REST summary for an exact (or near-exact) title. Returns the
// decoded JSON object, or null on any 404/failure. Titles with spaces work
// fine URL-encoded; Wikipedia's own endpoint handles the redirect/case
// normalisation for close matches itself.
function wiki_summary(string $title): ?array {
    $key = 'wikisum:' . mb_strtolower($title);
    if (($c = df_cache_get($key, 604800)) !== null) {
        $d = json_decode($c, true);
        return is_array($d) ? ($d ?: null) : null;
    }
    $r = http_get('https://en.wikipedia.org/api/rest_v1/page/summary/' . rawurlencode(str_replace(' ', '_', $title)),
                   3000000, WIKI_UA);
    if ($r === null || ($r['status'] ?? 200) >= 400) return null;
    $j = json_decode($r['body'], true);
    if (!is_array($j) || empty($j['title'])) return null;
    df_cache_put($key, json_encode($j));
    return $j;
}

// Resolve a fuzzy query to the nearest real article title via opensearch, or
// null if nothing matches. Failures aren't cached -- same "never cache a
// miss" rule as map_geocode, so a transient upstream hiccup can't freeze a
// real title as permanently unfindable.
function wiki_resolve(string $q): ?string {
    $r = http_get_cached('https://en.wikipedia.org/w/api.php?action=opensearch&format=json&limit=1&search='
        . urlencode($q), 604800, 3000000, WIKI_UA);
    if ($r === null) return null;
    $j = json_decode($r['body'], true);
    return (is_array($j) && !empty($j[1][0])) ? (string)$j[1][0] : null;
}
