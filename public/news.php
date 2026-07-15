<?php
// DuckFind News — a 68k.news-style front page. Feeds are grouped into sections,
// merged, date-sorted, and rendered as plain-HTML headlines that open in the
// reader. The whole assembled page is cached ~1 hour per display-variant, so
// almost every view is served without touching the network or re-rendering.
require __DIR__ . '/lib.php';
if (!df_rate('news')) df_rate_block();
header('Content-Type: text/html; charset=iso-8859-1');

// Section => [source name => feed URL], from config (see config.example.php).
$SECTIONS = df_cfg('news_sections', []);

// Full-page cache. The rendered HTML depends on the visitor's display cookies
// (images on/off, colour mode, dark theme), so those form the cache variant —
// at most a handful of variants, each good for an hour. A missing/degraded
// render (a dead feed served stale, or an empty section) is shown but NOT
// cached, so a transient upstream failure can't stick around for the hour.
// Normalise the variant to the finite set that actually changes rendering
// (images on/off, colour mode, theme, text size) BEFORE keying — otherwise an
// attacker loops unique cookie values to mint unbounded distinct cache files.
$vImg  = (($_COOKIE['df_img'] ?? '1') === '0') ? '0' : '1';
$vMode = in_array($_COOKIE['df_mode'] ?? 'color', ['gray', 'bw'], true) ? $_COOKIE['df_mode'] : 'color';
$vText = (($_COOKIE['df_text'] ?? 'normal') === 'large') ? 'L' : 'n';   // text size affects the render
$ckey  = 'newspage:' . $vImg . ':' . $vMode . ':' . (df_dark() ? 'd' : 'l') . ':' . $vText;
if (($cached = df_cache_get($ckey, 3600)) !== null) { echo $cached; exit; }

ob_start();
echo page_head(DUCKFIND_NAME . ' - news');
echo '<form action="/" method="get"><a href="/"><b>' . DUCKFIND_NAME . '</b></a>&nbsp;&nbsp;'
   . '<input type="text" name="q" size="28">&nbsp;<input type="submit" value="Quack!"></form>';

// section jump-nav
$nav = [];
foreach (array_keys($SECTIONS) as $sec) $nav[] = '<a href="#' . df_slug($sec) . '">' . e($sec) . '</a>';
echo '<font size="1">News &middot; ' . implode(' &middot; ', $nav)
   . ' &nbsp;|&nbsp; <a href="/feeds.php">my feeds</a> &middot; '
   . '<a href="/hn.php">hacker news</a></font><hr>';

if (!$SECTIONS) {
    echo '<p>No news sections are configured. See <tt>news_sections</tt> in '
       . '<tt>config.php</tt>.</p>';
}

// Whole-page fetch budget: news has many feeds (12 by default) and each cold
// one is a real HTTP fetch, so a single dead feed shouldn't hang every view.
// Fetch fresh until the budget is spent, then serve cached copies for the rest.
$deadline = microtime(true) + 8.0;
$healthy = ($SECTIONS !== []);
foreach ($SECTIONS as $section => $feeds) {
    $items = [];
    foreach ($feeds as $name => $url) {
        if (microtime(true) < $deadline) {
            $its = df_feed_items($url, 8);
        } else {
            $its = df_feed_items_stale($url, 8);
            $healthy = false;                        // served something stale
        }
        foreach ($its as $it) { $it['src'] = $name; $items[] = $it; }
    }
    usort($items, fn($a, $b) => ($b['ts'] ?? 0) <=> ($a['ts'] ?? 0));   // newest first
    $items = array_slice($items, 0, 10);   // 10/section stays generous and keeps the page light

    echo '<a name="' . df_slug($section) . '"></a><h2>' . e($section) . '</h2>';
    if (!$items) { echo '<p><font size="1">(section unavailable)</font></p>'; $healthy = false; continue; }
    echo df_river($items, true);
}
echo page_foot();

$html = ob_get_clean();
if ($healthy) df_cache_put($ckey, $html);   // only cache a clean, complete render
echo $html;
