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
$vMode = df_page_img_mode($_COOKIE['df_mode'] ?? 'color');
$vText = (($_COOKIE['df_text'] ?? 'normal') === 'large') ? 'L' : 'n';   // text size affects the render
// The config is part of the key (2026-11-12): changing news_sections or the
// favicon switch on the server takes effect at once instead of serving the old
// page for up to an hour.
$vCfg  = substr(sha1(serialize([df_cfg('news_sections', null), df_cfg('news_favicons', null)])), 0, 8);
$ckey  = 'newspage:' . $vImg . ':' . $vMode . ':' . (df_dark() ? 'd' : 'l') . ':' . $vText . ':' . $vCfg;
if (($cached = df_cache_get($ckey, 3600)) !== null) { echo $cached; exit; }

ob_start();
echo page_head(DUCKFIND_NAME . ' - news');
echo '<form action="/" method="get">' . df_brand_link() . '&nbsp;&nbsp;'
   . '<input type="text" name="q" size="28">&nbsp;<input type="submit" value="Quack!"></form>';

// section jump-nav
$nav = [];
foreach (array_keys($SECTIONS) as $sec) $nav[] = '<a href="#' . df_slug($sec) . '">' . e($sec) . '</a>';
// one clear line down from the search box (directly under Quack! it read as cramped)
echo '<br><font size="1">News &middot; ' . implode(' &middot; ', $nav)
   . ' &nbsp;|&nbsp; <a href="/feeds.php">my feeds</a> &middot; '
   . '<a href="/hn.php">hacker news</a></font><hr>';

if (!$SECTIONS) {
    echo '<p>No news sections are configured. See <tt>news_sections</tt> in '
       . '<tt>config.php</tt>.</p>';
}

// Whole-page fetch budget: news has many feeds (~35 by default) and each cold
// one is a real HTTP fetch, so a single dead or slow feed shouldn't hang every
// view. Each fetch gets at most 5 s and never more than the budget left; once
// the budget is spent the rest come from cached copies (up to a day old), and
// the page isn't cached, so the next view fetches more. df_feed_items itself
// falls back to the cached copy when a feed fails.
$deadline = microtime(true) + (float)df_cfg('news_budget_seconds', 10);
$healthy = ($SECTIONS !== []);
foreach ($SECTIONS as $section => $feeds) {
    $items = [];
    foreach ($feeds as $name => $url) {
        $left = $deadline - microtime(true);
        if ($left > 0.5) {
            $its = df_feed_items($url, 8, (int)max(1, min(5, floor($left))));
        } else {
            $its = df_feed_items_stale($url, 8);
            $healthy = false;                        // served something stale
        }
        foreach ($its as $it) { $it['src'] = $name; $items[] = $it; }
    }
    // fair mixing: at most 3 items from any one source, 10 per section, newest first
    $items = df_feed_mix($items, 3, 10);

    echo '<a name="' . df_slug($section) . '"></a><h2>' . e($section) . '</h2>';
    if (!$items) { echo '<p><font size="1">(section unavailable)</font></p>'; $healthy = false; continue; }
    echo df_river($items, true);
}
echo page_foot();

$html = ob_get_clean();
if ($healthy) df_cache_put($ckey, $html);   // only cache a clean, complete render
echo $html;
