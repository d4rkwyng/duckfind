<?php
// DuckFind News — a 68k.news-style front page. Feeds are grouped into sections,
// merged, date-sorted, and rendered as plain-HTML headlines that open in the
// reader. Feeds cached 15 minutes.
require __DIR__ . '/lib.php';
if (!df_rate('news')) df_rate_block();
header('Content-Type: text/html; charset=iso-8859-1');

// Section => [source name => feed URL], from config (see config.example.php).
$SECTIONS = df_cfg('news_sections', []);

echo page_head(DUCKFIND_NAME . ' News');
echo '<form action="/" method="get"><a href="/"><b>' . DUCKFIND_NAME . '</b></a>&nbsp;&nbsp;'
   . '<input type="text" name="q" size="28">&nbsp;<input type="submit" value="Search"></form>';

// section jump-nav
$nav = [];
foreach (array_keys($SECTIONS) as $sec) $nav[] = '<a href="#' . rawurlencode($sec) . '">' . e($sec) . '</a>';
echo '<font size="1">News &middot; ' . implode(' &middot; ', $nav) . '</font><hr>';

foreach ($SECTIONS as $section => $feeds) {
    $items = [];
    foreach ($feeds as $name => $url) {
        foreach (df_feed_items($url, 8) as $it) { $it['src'] = $name; $items[] = $it; }
    }
    usort($items, fn($a, $b) => ($b['ts'] ?? 0) <=> ($a['ts'] ?? 0));   // newest first
    $items = array_slice($items, 0, 12);

    echo '<a name="' . rawurlencode($section) . '"></a><h2>' . e($section) . '</h2>';
    if (!$items) { echo '<p><font size="1">(section unavailable)</font></p>'; continue; }
    echo '<ul>';
    foreach ($items as $it) {
        echo '<li><a href="/read.php?url=' . htmlspecialchars(urlencode($it['link']), ENT_QUOTES) . '">'
           . e($it['title']) . '</a> <font size="1" color="#777777">&ndash; ' . e($it['src']) . '</font></li>';
    }
    echo '</ul>';
}
echo page_foot();

function df_feed_items(string $url, int $limit): array {
    if (($c = df_cache_get('feed:' . $url, 900)) !== null) {
        $d = @unserialize($c);
        if (is_array($d)) return $d;
    }
    $out = [];
    $r = http_get($url, 2000000);
    if ($r !== null) {
        $xml = @simplexml_load_string($r['body'], 'SimpleXMLElement', LIBXML_NOCDATA | LIBXML_NONET);
        if ($xml !== false) {
            if (isset($xml->channel->item)) {                 // RSS 2.0
                foreach ($xml->channel->item as $it) {
                    $out[] = [
                        'title' => trim((string)$it->title),
                        'link'  => trim((string)$it->link),
                        'ts'    => strtotime((string)$it->pubDate) ?: 0,
                    ];
                    if (count($out) >= $limit) break;
                }
            } elseif (isset($xml->entry)) {                    // Atom
                foreach ($xml->entry as $en) {
                    $link = '';
                    foreach ($en->link as $l) {
                        $rel = (string)($l['rel'] ?? 'alternate');
                        if ($rel === 'alternate' || $link === '') $link = (string)$l['href'];
                    }
                    $when = (string)($en->published ?? '') ?: (string)($en->updated ?? '');
                    $out[] = ['title' => trim((string)$en->title), 'link' => $link, 'ts' => strtotime($when) ?: 0];
                    if (count($out) >= $limit) break;
                }
            }
        }
    }
    $out = array_values(array_filter($out,
        fn($i) => $i['title'] !== '' && preg_match('#^https?://#i', $i['link'])));
    df_cache_put('feed:' . $url, serialize($out));
    return $out;
}
