<?php
require __DIR__ . '/lib.php';
if (!df_rate('read')) df_rate_block();
header('Content-Type: text/html; charset=iso-8859-1');

$url = df_input('url');
if ($url !== '' && !preg_match('#^[a-z]+://#i', $url)) $url = 'https://' . $url;

// display prefs: an explicit query param wins, else the saved cookie, else default
$prefImg = ($_COOKIE['df_img'] ?? '1') !== '0';
define('DF_IMAGES', isset($_GET['img']) ? ($_GET['img'] !== '0') : $prefImg);
// colour rendering: color (default), gray, or bw (dithered) -- for low-colour
// displays -- or ascii: images inlined as text art, for browsers with no <img>
// at all (Lynx, MacWeb). See df_ascii_inline() in lib.php.
// output format: html (default) or plain text (?fmt=txt) for MacLynx / Apple II
$fmt = (($_GET['fmt'] ?? '') === 'txt') ? 'txt' : 'html';
$prefMode = df_page_img_mode($_GET['im'] ?? ($_COOKIE['df_mode'] ?? 'color'));
// plain text collapses runs of spaces, which would shred the art -- so txt
// output keeps its old behaviour (images simply drop out) and fetches nothing
define('DF_IMGMODE', ($fmt === 'txt' && $prefMode === 'ascii') ? 'color' : $prefMode);
// Wayback Machine: ?year=YYYY (or full 14-digit timestamp) reads an archived copy
define('DF_YEAR', preg_replace('/\D/', '', df_str($_GET['year'] ?? '')));
// Render mode: reader (extract the article) vs original layout (pass through,
// preserving tables/fonts/image-nav). Original is the default for Wayback, since
// era-appropriate pages were built for old browsers; reader for live pages.
$rawParam = $_GET['raw'] ?? '';
define('DF_RAW', $rawParam === '1' || ($rawParam === '' && DF_YEAR !== ''));

if (!preg_match('#^https?://#i', $url)) {
    echo page_head(DUCKFIND_NAME . ' - reader', true);
    echo '<form action="/read.php" method="get">' . df_brand_link() . '&nbsp;&nbsp;'
       . 'Read: <input type="text" name="url" size="34" value="' . e($url) . '">&nbsp;'
       . '<input type="submit" value="Read"></form><hr>';
    echo '<p>Paste any web address and get the page stripped to clean, readable HTML -- '
       . 'no scripts, no stylesheets, images converted for vintage screens.</p>';
    echo '<p><font size="1">Time-travel: add a year to read a page as it was '
       . '(<tt>!wb url 1999</tt> from the search box). '
       . '[<a href="/wiby.php">classic web search</a>] '
       . '[<a href="/wiby.php?surprise=1">surprise me</a>]</font></p>';
    echo page_foot();
    exit;
}

// From here on this does a real outbound fetch -- gate it (see lib.php).
df_require_browser_proof();

// Wayback: rewrite the fetch through web.archive.org when a year is given.
// The "id_" suffix returns the original archived bytes without the WB toolbar.
$ts = '';
if (DF_YEAR !== '') {
    $ts = DF_YEAR;
    if (strlen($ts) === 4) $ts .= '0601';                 // bare year -> mid-year
    $ts = substr(str_pad($ts, 14, '0'), 0, 14);
}
// Site-wide hourly budget on uncached reads (see lib.php): a cache hit is free,
// and a signed link from one of DuckFind's own pages (t=, df_readtok) skips the
// hourly reserve up to its own ceiling. A bad or missing t just falls through.
if (!df_read_cached($url, $ts)
    && !df_read_token_bypass_ok($url, df_str($_GET['t'] ?? ''))
    && !df_read_budget_ok()) df_read_budget_block();
$res = $ts !== '' ? df_wayback_get($ts, $url, 86400) : http_get_cached($url, 1800);
// PDFs aren't HTML — hand them to the PDF viewer (poppler-backed) instead of
// failing. Detect by content-type or the %PDF magic, preserving the Wayback era.
if ($res !== null && (stripos((string)$res['ctype'], 'application/pdf') !== false
    || strncmp((string)$res['body'], '%PDF', 4) === 0)) {
    header('Location: /pdf.php?url=' . urlencode($url) . (DF_YEAR !== '' ? '&year=' . DF_YEAR : ''),
           true, 302);
    exit;
}
// Empty/whitespace body (empty 200, 204, blank CDN edge page) has no parseable
// DOM — extraction would hit a null documentElement and fatal. Treat it as a
// load failure instead of crashing.
if ($res === null || trim((string)$res['body']) === ''
    || ($res['ctype'] !== '' && !preg_match('#text/html|application/xhtml#i', $res['ctype']))) {
    // offer a Wayback snapshot if the live page is gone; explain Archive throttling
    $extra = '';
    if (DF_YEAR !== '') {
        $extra = '<p>The Internet Archive may be rate-limiting right now -- wait a few '
               . 'seconds and reload, or try a different year from the toolbar.</p>';
    } else {
        $av = http_get('https://archive.org/wayback/available?url=' . urlencode($url), 200000, '', null, 4);
        if ($av && ($j = json_decode($av['body'], true))
            && !empty($j['archived_snapshots']['closest']['timestamp'])) {
            $ty = substr($j['archived_snapshots']['closest']['timestamp'], 0, 4);
            $uu = htmlspecialchars(urlencode($url), ENT_QUOTES);
            $extra = '<p><b>The live page didn\'t load</b> -- but the Wayback Machine has a copy from '
                   . e($ty) . '. [<a href="/read.php?url=' . $uu . '&amp;year=' . e($ty) . '">read the '
                   . e($ty) . ' version</a>]</p>';
        }
    }
    echo page_head('Read a page', true)
       . '<p><b>Could not load</b> <tt>' . e($url) . '</tt></p>' . $extra
       . '<p>[<a href="' . e($url) . '">try it directly</a>]</p>' . page_foot();
    exit;
}

// Original-layout mode passes the page through; reader mode (and plain-text)
// extracts the article. Recipe pages (schema.org/Recipe JSON-LD) get a clean
// ingredients+steps card instead of letting Readability wade through the
// life-story and ad-wall — the reader's single worst-case input.
$next = ''; $prev = '';
// Relative links resolve against where the page actually came from: after a
// redirect (typically "/docs" -> "/docs/") the requested URL is the wrong base.
// Wayback bodies keep the original URL as base (the archive's own URL is not).
$baseUrl = (DF_YEAR === '' && !empty($res['url']) && preg_match('#^https?://#i', (string)$res['url']))
         ? (string)$res['url'] : $url;
[$title, $content, $next, $prev] = read_extract($res['body'], $baseUrl, (string)$res['ctype'], $fmt);
$plain = trim(preg_replace('/\s+/', ' ', strip_tags($content)));

// Render fallback (lib.php, df_render_fetch): a live page whose own HTML
// extracts to almost nothing is usually built by JavaScript. Ask the render
// service for the rendered DOM and extract that instead -- only if it yields
// more text. A real bot/JS CHALLENGE (captcha, "checking your browser") is
// never sent to the renderer; a plain "enable JavaScript" notice is exactly
// the JS-built case and is. The block check below runs on the final result.
$renderNote = ''; $rendered = false;
if (DF_YEAR === '' && (int)($res['status'] ?? 200) === 200 && df_render_enabled()
    && strlen($plain) < (int)df_cfg('render_min_text', 400)
    && !preg_match(DF_CHALLENGE_RE, $title . ' ' . $plain)) {
    $rr = df_render_fetch($url);
    if ($rr === 'failed' || $rr === 'unavailable') {
        $renderNote = 'This page needs JavaScript, and ' . DUCKFIND_NAME . '&#39;s page renderer '
                    . 'couldn&#39;t render it right now, so this is the page without it. '
                    . 'Try again in a few minutes.';
    } elseif ($rr === 'capped') {
        $renderNote = 'This page needs JavaScript, and ' . DUCKFIND_NAME . '&#39;s page renderer '
                    . 'has done all it can for this hour. Try again after the top of the hour.';
    } elseif (is_array($rr)) {
        $rbase = preg_match('#^https?://#i', (string)$rr['final_url']) ? (string)$rr['final_url'] : $url;
        [$t2, $c2, $n2, $p2] = read_extract((string)$rr['html'], $rbase, 'text/html; charset=utf-8', $fmt);
        $plain2 = trim(preg_replace('/\s+/', ' ', strip_tags($c2)));
        if (strlen($plain2) > strlen($plain)) {           // longer wins
            [$title, $content, $next, $prev, $plain, $baseUrl] = [$t2, $c2, $n2, $p2, $plain2, $rbase];
            df_daily_inc('renderok');
            $rendered = true;
            $renderNote = 'This page is built by JavaScript, so ' . DUCKFIND_NAME
                        . ' ran it on a separate server first.';
        }
    }
}

// Anti-bot / JS-challenge interstitial? Show a useful message rather than
// rendering "Just a moment..." as if it were the article. (Reader-mode only —
// a full challenge page in original mode would be large and not match.)
// A short extract that either matches a known bot/paywall/block phrase OR came
// back with an HTTP 4xx/5xx status is almost never real article content — show
// the "blocked, try Wayback" page instead of rendering the stub as the article.
if (strlen($plain) < 600 && (($res['status'] ?? 200) >= 400
    || preg_match(DF_CHALLENGE_RE, $title . ' ' . $plain)
    // a leftover <noscript> "enable JavaScript" in a page we rendered is not a block
    || (!$rendered && preg_match('/enable javascript|enable js/i', $title . ' ' . $plain)))) {
    $uu = htmlspecialchars(urlencode($url), ENT_QUOTES);
    $wbl = '';
    if (DF_YEAR === '') {
        $av = http_get('https://archive.org/wayback/available?url=' . urlencode($url), 200000, '', null, 4);
        if ($av && ($j = json_decode($av['body'], true))
            && !empty($j['archived_snapshots']['closest']['timestamp'])) {
            $ty = substr($j['archived_snapshots']['closest']['timestamp'], 0, 4);
            $wbl = ' &middot; [<a href="/read.php?url=' . $uu . '&amp;year=' . e($ty)
                 . '">read the ' . e($ty) . ' Wayback copy</a>]';
        }
    }
    echo page_head('Blocked by site', true)
       . '<h1>Site is blocking automated access</h1>'
       . '<p>This page returned a bot or JavaScript challenge instead of its content, '
       . 'so there is nothing to read.</p>'
       . '<p>[<a href="' . e($url) . '">try it directly</a>]' . $wbl . '</p>' . page_foot();
    exit;
}

// plain-text mode: emit text/plain for terminal/text browsers and offline saving
if ($fmt === 'txt') {
    header('Content-Type: text/plain; charset=utf-8');
    [$content, $refs, $unnumbered] = rd_txt_number_links($content, DF_YEAR);
    $t = preg_replace('#<li\b[^>]*>#i', "\n * ", $content);
    $t = preg_replace('#</(p|h[1-6]|tr|div|blockquote)>#i', "\n\n", $t);
    $t = preg_replace('#<(br|hr)\b[^>]*>#i', "\n", $t);
    $t = html_entity_decode(strip_tags($t), ENT_QUOTES, 'UTF-8');
    $t = preg_replace('/[ \t]+/', ' ', $t);
    $t = preg_replace('/\n{3,}/', "\n\n", $t);
    if ($title !== '') echo df_translit($title) . "\n" . str_repeat('=', min(70, strlen($title))) . "\n\n";
    echo trim(df_translit($t)) . "\n";
    if ($refs) {
        echo "\nReferences\n\n";
        foreach ($refs as $i => $r) echo ' ' . ($i + 1) . '. ' . $r . "\n";
        if ($unnumbered > 0) echo "\n (and " . $unnumbered . " more links, not numbered)\n";
    }
    echo "\n----\nsource: " . $url . "\n";
    exit;
}

$uq = htmlspecialchars(urlencode($url), ENT_QUOTES);
$yp = DF_YEAR !== '' ? '&amp;year=' . DF_YEAR : '';        // thread Wayback era through links
$rp = '&amp;raw=' . (DF_RAW ? '1' : '0');                  // thread render mode through links
// images: "off" sits as a peer option alongside the color modes, same bold-
// when-active idiom throughout -- previously "[text only]" (toggles images)
// and "[plain text]" (switches the whole page to a raw text document, a
// totally different thing) sat right next to each other on the toolbar and
// read like near-synonyms. Keeping image handling and content format as two
// clearly separate groups removes that ambiguity instead of just relabeling it.
$imgLinks = [];
$imgLinks[] = !DF_IMAGES ? '<b>off</b>'
    : '<a href="/read.php?url=' . $uq . '&amp;img=0' . $yp . $rp . '">off</a>';
foreach (['color' => 'color', 'gray' => 'gray', 'bw' => 'b&amp;w', 'ascii' => 'ascii'] as $k => $label) {
    $href = '/read.php?url=' . $uq . '&amp;img=1' . ($k !== 'color' ? '&amp;im=' . $k : '') . $yp . $rp;
    $imgLinks[] = (DF_IMAGES && $k === DF_IMGMODE) ? "<b>$label</b>" : '<a href="' . $href . '">' . $label . '</a>';
}
$toggle = 'images: ' . implode(' ', $imgLinks);
// view picker: reader/original are two HTML renders of the same article;
// plain text is a third rendering of it (not an image setting), so it joins
// this group instead of sitting next to the image toggle where it read as a
// near-duplicate of "off".
$toggle .= ' &middot; view: '
    . (DF_RAW ? '<a href="/read.php?url=' . $uq . '&amp;raw=0' . $yp . '">reader</a>' : '<b>reader</b>')
    . ' '
    . (DF_RAW ? '<b>original</b>' : '<a href="/read.php?url=' . $uq . '&amp;raw=1' . $yp . '">original</a>')
    . ' <a href="/read.php?url=' . $uq . '&amp;fmt=txt' . $yp . '">plain text</a>';

// #10 multi-page stitching: the article's own "next page" / "previous page"
// links, routed back through the reader with the same display prefs
$np = (DF_IMAGES ? '' : '&amp;img=0') . (DF_IMGMODE !== 'color' ? '&amp;im=' . DF_IMGMODE : '') . $yp . $rp;
$pageHref = function (string $rel) use ($baseUrl, $np): string {
    if ($rel === '') return '';
    $abs = absolutize($baseUrl, $rel);
    return preg_match('#^https?://#i', $abs)
        ? '/read.php?url=' . htmlspecialchars(urlencode($abs), ENT_QUOTES) . $np . df_readtok_qs($abs, true) : '';
};
$nextHref = $pageHref($next);
$prevHref = $pageHref($prev);

// Long articles in parts (for low-RAM vintage machines): reader mode only,
// 'read_page_bytes' per part (0 = off). Parts are slices of this same
// extraction, so part N costs a cache hit, not a fetch.
$parts = (!DF_RAW) ? rd_paginate($content, (int)df_cfg('read_page_bytes', 32768)) : [$content];
$partCount = count($parts);
$part = max(1, min($partCount, (int)($_GET['pt'] ?? 1)));
$partNav = '';
if ($partCount > 1) {
    $tq = df_str($_GET['t'] ?? '');
    $tq = preg_match('/^[0-9a-f]{1,64}$/', $tq) ? '&amp;t=' . $tq : '';   // carry the read token
    $partHref = function (int $n) use ($uq, $np, $tq): string {
        return '/read.php?url=' . $uq . $np . $tq . ($n > 1 ? '&amp;pt=' . $n : '');
    };
    $parts = rd_link_parts($parts, $partHref);
    $nav = ['Page ' . $part . ' of ' . $partCount];
    if ($part > 1) $nav[] = '<a href="' . $partHref($part - 1) . '">&lt; Previous</a>';
    if ($part < $partCount) $nav[] = '<a href="' . $partHref($part + 1) . '">Next &gt;</a>';
    $partNav = '<p align="center"><font size="1"><b>' . implode(' &middot; ', $nav) . '</b></font></p>';
}
$content = $parts[$part - 1];

echo page_head($title !== '' ? $title : $url, true, '',
               $prevHref !== '' ? '<link rel="prev" href="' . $prevHref . '">' . "\n" : '');
echo '<form action="/" method="get">' . df_brand_link() . '&nbsp;&nbsp;'
   . '<input type="text" name="q" size="24">&nbsp;<input type="submit" value="Quack!"></form>';
// toolbar on its own line below the search box (jammed onto the search line it
// wrapped on an 800x600 screen)
echo '<font size="1">' . $toggle . '</font><br>';
echo '<font size="1">Reading: <a href="' . e($url) . '">' . e(df_shorten($url)) . '</a></font><br>';
// Wayback era switcher — flip the current page to an archived year in one click.
// Lists only the years the Archive actually holds a capture of this URL (CDX,
// see lib.php), linking each to that year's real capture timestamp. Read from
// cache only -- never a network call during the render; on a miss (or while
// IA is throttling) it falls back to the fixed years, and the cache is warmed
// after the page is sent, in Wayback mode only (bottom of this file).
$wbYears = df_wayback_years_cached($url);
$wbLinks = [];
if ($wbYears === null) {
    foreach (['1998', '2002', '2006', '2010', '2015', '2020'] as $yr) $wbLinks[$yr] = $yr;
} else {
    foreach ($wbYears as $yr => $wts) $wbLinks[(string)$yr] = (string)$wts;
    // keep the era being read on the bar even if CDX doesn't list it
    $cur = DF_YEAR !== '' ? substr(DF_YEAR, 0, 4) : '';
    if ($cur !== '' && !isset($wbLinks[$cur])) { $wbLinks[$cur] = DF_YEAR; ksort($wbLinks, SORT_STRING); }
    $wbLinks = df_wayback_thin($wbLinks, $cur, 12);   // one line at 640/800 px wide
}
$wb = '<font size="1">Wayback:';
if (!$wbLinks) $wb .= ' <i>no archived copies</i>';
foreach ($wbLinks as $yr => $wts) {
    $yr  = (string)$yr;
    $lbl = "'" . substr($yr, 2, 2);
    $on = (DF_YEAR !== '' && substr(DF_YEAR, 0, 4) === $yr);
    $wb .= ' ' . ($on ? "<b>[$lbl]</b>"
                      : '<a href="/read.php?url=' . $uq . '&amp;year=' . e($wts) . $rp . '">' . $lbl . '</a>');
}
$wb .= DF_YEAR !== '' ? ' &middot; <a href="/read.php?url=' . $uq . '"><b>live</b></a>' : ' &middot; <i>live</i>';
echo $wb . '</font><hr>';
if ($title !== '') echo '<h1>' . e($title) . '</h1>';
if ($renderNote !== '') echo '<p><font size="1">' . $renderNote . '</font></p>';
echo $partNav;
echo $content;
echo $partNav;

// #10 multi-page stitching: previous/next page links (hrefs built above)
$pager = [];
if ($prevHref !== '') $pager[] = '<a href="' . $prevHref . '"><b>&lt; Previous page</b></a>';
if ($nextHref !== '') $pager[] = '<a href="' . $nextHref . '"><b>Next page &gt;</b></a>';
if ($pager) echo '<hr><p align="center">' . implode(' &nbsp; ', $pager) . '</p>';
echo page_foot();

// Warm the switcher's capture-year cache AFTER the visitor has the whole page
// (CDX answers take seconds). Only under php-fpm, where the response can be
// closed first; elsewhere the switcher just keeps the fixed years.
// Privacy: only in Wayback mode (DF_YEAR set), where this URL has already gone
// to the Archive because the visitor asked for an archived copy. A live read
// never sends the URL to archive.org; it shows the fixed years until someone's
// first Wayback click on that URL warms the cache.
if ($wbYears === null && DF_YEAR !== '' && function_exists('fastcgi_finish_request')) {
    fastcgi_finish_request();
    df_wayback_years_fill($url);
}

// ---------------------------------------------------------------------------
// Plain-text mode links (added 2026-11-12): Lynx-style "text[n]" markers plus
// a References list, so a text browser user can still follow links (by typing
// or copying the URL). Each reference is the absolute duckfind reader URL for
// the target, in plain-text mode (dl.php links stay dl.php), built from
// 'base_url'. Signed with the read token since 2026-11-12, like the HTML
// reader's in-page links: while a swarm keeps the hourly read budget spent, an
// unsigned link from a text browser hit a picture check it cannot show. Still
// bounded by the site-wide token ceiling (read_token_hourly_mult).
// In-page #links are left as plain text. Capped at $maxRefs (150) numbered
// links; the rest keep their text, unnumbered, and are counted. (A parameter,
// not a const: read.php exits before a file-level const below would run.)
function rd_txt_number_links(string $html, string $year = '', int $maxRefs = 150): array {
    $base = rtrim((string)df_cfg('base_url', 'http://duckfind.com'), '/');
    $refs = []; $more = 0;
    $out = preg_replace_callback('#<a\b([^>]*)>(.*?)</a>#is', function ($m) use (&$refs, &$more, $base, $year, $maxRefs) {
        $inner = $m[2];
        if (!preg_match('#\bhref\s*=\s*"([^"]*)"#i', $m[1], $h)) return $inner;   // named anchor
        $href = html_entity_decode($h[1], ENT_QUOTES, 'UTF-8');
        if ($href === '' || $href[0] === '#' || trim(strip_tags($inner)) === '') return $inner;
        $target = '';
        if (preg_match('#^/read\.php\?(.*)$#', $href, $q)) {
            parse_str($q[1], $qs);
            $u = is_string($qs['url'] ?? null) ? $qs['url'] : '';
            if ($u === '') return $inner;
            $target = $base . '/read.php?url=' . urlencode($u) . '&fmt=txt'
                    . ($year !== '' ? '&year=' . urlencode($year) . '&raw=0' : '')
                    . df_readtok_qs($u);                          // signed, like the HTML reader's links
        } elseif ($href[0] === '/') {
            $target = $base . $href;                              // dl.php and other local tools
        } elseif (preg_match('#^https?://#i', $href)) {
            $target = $href;
        } else {
            return $inner;
        }
        if (count($refs) >= $maxRefs) { $more++; return $inner; }
        $refs[] = $target;
        return $inner . '[' . count($refs) . ']';
    }, $html);
    return [$out ?? $html, $refs, $more];
}

// Split reader HTML into parts of about $max bytes (added 2026-11-12) at block
// boundaries only: after </p>, </pre>, </table>, </ul>, </ol>, </dl>,
// </blockquote> or a closing heading at the top level -- never inside <pre>,
// <table>, <dl>, <blockquote> or <center>, so every part is balanced HTML. A
// long TOP-LEVEL <ul>/<ol> (e.g. a footnote list) may also be cut between its
// items: the part closes the list and the next part reopens it, an <ol> with
// start= so numbering continues. A single block larger than $max that can't
// be cut stays whole (a part may exceed $max). A last part under $max/8 is
// folded into the one before it. $max <= 0, or content within $max, returns
// [$html].
function rd_paginate(string $html, int $max): array {
    if ($max <= 0 || strlen($html) <= $max) return [$html];
    $containers = ['pre', 'table', 'ul', 'ol', 'dl', 'blockquote', 'center'];
    $ends = ['p', 'pre', 'table', 'ul', 'ol', 'dl', 'blockquote', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'];
    preg_match_all('#<(/?)([a-z][a-z0-9]*)\b[^>]*>#i', $html, $tags, PREG_OFFSET_CAPTURE | PREG_SET_ORDER);
    // cut candidates: [offset, html to close the part with, html to open the next with]
    $cuts = []; $stack = []; $listOpen = ''; $listName = ''; $listStart = 1; $items = 0;
    foreach ($tags as $t) {
        $closing = $t[1][0] === '/';
        $name = strtolower($t[2][0]);
        $end = $t[0][1] + strlen($t[0][0]);
        if (in_array($name, $containers, true)) {
            if (!$closing) {
                if (!$stack && ($name === 'ul' || $name === 'ol')) {
                    $listOpen = $t[0][0]; $listName = $name; $items = 0;
                    $listStart = preg_match('#\bstart\s*=\s*"?(\d+)#i', $t[0][0], $sm) ? (int)$sm[1] : 1;
                }
                $stack[] = $name;
            } elseif ($stack) {
                array_pop($stack);
            }
        }
        if ($closing && !$stack && in_array($name, $ends, true)) {
            $cuts[] = [$end, '', ''];
        } elseif ($closing && $name === 'li' && count($stack) === 1 && $stack[0] === $listName && $listName !== '') {
            $items++;
            $reopen = $listName === 'ol'
                ? preg_replace('#\s+start\s*=\s*"?\d+"?#i', '', substr($listOpen, 0, -1)) . ' start="' . ($listStart + $items) . '">'
                : $listOpen;
            $cuts[] = [$end, '</' . $listName . '>', $reopen];
        }
    }
    $parts = []; $start = 0; $prefix = ''; $suffix = ''; $last = null;
    foreach ($cuts as $c) {
        if ($c[0] - $start >= $max) {
            $at = ($last !== null && $last[0] > $start) ? $last : $c;  // stay within $max if we can
            $parts[] = $prefix . substr($html, $start, $at[0] - $start) . $at[1];
            $start = $at[0];
            $suffix = $at[1];
            $prefix = $at[2];
        }
        $last = $c;
    }
    $rest = $prefix . substr($html, $start);
    if ($parts && (trim(strip_tags($rest)) === '' || strlen($rest) < intdiv($max, 8))) {
        // fold a near-empty tail into the part before; drop its reopen/close pair
        $prev = array_pop($parts);
        if ($prefix !== '' && $suffix !== '' && substr($prev, -strlen($suffix)) === $suffix
            && strpos($rest, $prefix) === 0) {
            $prev = substr($prev, 0, -strlen($suffix));
            $rest = substr($rest, strlen($prefix));
        }
        $parts[] = $prev . $rest;
    } elseif ($rest !== '') {
        $parts[] = $rest;
    }
    return $parts ?: [$html];
}

// In-page links whose target landed in another part link to that part
// (best effort: targets are the <a name> anchors render_node emits).
function rd_link_parts(array $parts, callable $partHref): array {
    $where = [];
    foreach ($parts as $i => $p) {
        if (preg_match_all('#<a name="([^"]+)"></a>#', $p, $m)) {
            foreach ($m[1] as $n) $where[$n] = $i;
        }
    }
    foreach ($parts as $i => $p) {
        $parts[$i] = preg_replace_callback('#<a href="\#([^"]+)">#', function ($m) use ($where, $i, $partHref) {
            $name = rawurldecode(html_entity_decode($m[1], ENT_QUOTES, 'UTF-8'));
            $key = htmlspecialchars($name, ENT_QUOTES);
            if (!isset($where[$key]) || $where[$key] === $i) return $m[0];
            return '<a href="' . $partHref($where[$key] + 1) . '#' . $m[1] . '">';
        }, $p);
    }
    return $parts;
}

// ---------------------------------------------------------------------------

// If the page carries a schema.org/Recipe in JSON-LD, render a clean card
// (ingredients + numbered steps) and return [title, html]; else null. Fast
// string bail keeps this near-free on the vast majority of pages. Handles the
// usual schema variance: @graph wrappers, @type as string or array, image as
// string/array/ImageObject, instructions as string / string[] / HowToStep[] /
// HowToSection[].
// The reader's extraction for one fetched body: recipe card, original layout
// or Readability-style article, by mode. [title, content, next, prev].
function read_extract(string $body, string $baseUrl, string $ctype, string $fmt): array {
    $recipe = (!DF_RAW && $fmt !== 'txt') ? extract_recipe($body, $baseUrl) : null;
    if ($recipe !== null) return [$recipe[0], $recipe[1], '', ''];
    if (DF_RAW && $fmt !== 'txt') {
        [$t, $c] = render_original($body, $baseUrl, $ctype);
        return [$t, $c, '', ''];
    }
    return extract_readable($body, $baseUrl, $ctype);
}

function extract_recipe(string $html, string $baseUrl): ?array {
    if (stripos($html, 'ld+json') === false || stripos($html, 'Recipe') === false) return null;
    $dom = new DOMDocument();
    libxml_use_internal_errors(true);
    $dom->loadHTML('<?xml encoding="UTF-8" ?>' . df_to_utf8($html));
    libxml_clear_errors();
    $r = null;
    foreach ((new DOMXPath($dom))->query('//script[@type="application/ld+json"]') as $s) {
        $j = json_decode(trim($s->textContent), true);
        if (!is_array($j)) continue;
        foreach (rc_flatten($j) as $obj) {
            if (rc_is_type($obj, 'Recipe')) { $r = $obj; break 2; }
        }
    }
    if ($r === null) return null;

    $name = trim((string)rc_str($r['name'] ?? ''));
    $ings = [];
    foreach ((array)($r['recipeIngredient'] ?? $r['ingredients'] ?? []) as $i) {
        $i = trim((string)rc_str($i)); if ($i !== '') $ings[] = $i;
    }
    $steps = rc_steps($r['recipeInstructions'] ?? []);
    if (!$ings && !$steps) return null;                 // not enough to be worth a card

    $out = '';
    // hero image through the GIF proxy, honouring the visitor's display prefs
    if (DF_IMAGES && ($img = rc_image($r['image'] ?? null)) !== '') {
        $abs = absolutize($baseUrl, $img);
        if (DF_IMGMODE === 'ascii') {
            $art = df_ascii_inline($abs, DF_YEAR);
            $out .= $art ?? '<p>' . df_ascii_fallback($abs, $name) . '</p>';
        } else {
            $iq = '&amp;w=480' . (DF_IMGMODE !== 'color' ? '&amp;im=' . DF_IMGMODE : '');
            $out .= '<p><img src="/img.php?url=' . htmlspecialchars(urlencode($abs), ENT_QUOTES) . $iq
                  . '" alt="" border="0"></p>';
        }
    }
    $meta = [];
    foreach (['prepTime' => 'Prep', 'cookTime' => 'Cook', 'totalTime' => 'Total'] as $k => $lbl) {
        $d = rc_duration((string)($r[$k] ?? '')); if ($d !== '') $meta[] = $lbl . ': ' . $d;
    }
    if (!empty($r['recipeYield'])) $meta[] = 'Yield: ' . e(trim((string)rc_str($r['recipeYield'])));
    if ($meta) $out .= '<p><font size="1">' . implode(' &middot; ', $meta) . '</font></p>';
    if (!empty($r['description'])) $out .= '<p>' . e(trim((string)rc_str($r['description']))) . '</p>';

    if ($ings) {
        $out .= '<h2>Ingredients</h2><ul>';
        foreach ($ings as $i) $out .= '<li>' . e($i) . '</li>';
        $out .= '</ul>';
    }
    if ($steps) {
        $out .= '<h2>Instructions</h2><ol>';
        foreach ($steps as $st) $out .= '<li>' . e($st) . '</li>';
        $out .= '</ol>';
    }
    $out .= '<hr><p><font size="1">Recipe view -- [<a href="/read.php?url='
          . htmlspecialchars(urlencode($baseUrl), ENT_QUOTES) . '&amp;raw=1">full page</a>]</font></p>';
    return [$name !== '' ? $name : 'Recipe', $out];
}

// Flatten a JSON-LD blob into a list of candidate objects (handles @graph and
// arrays of objects at the top level). Only arrays come back: a scalar/null
// @graph entry reached rc_is_type(array) as a TypeError -- a 500 on any page
// with "Recipe" somewhere and a malformed JSON-LD block.
function rc_flatten($j): array {
    $out = [];
    if (isset($j['@graph']) && is_array($j['@graph'])) { foreach ($j['@graph'] as $g) if (is_array($g)) $out[] = $g; }
    $isList = $j === [] || array_keys($j) === range(0, count($j) - 1);   // 8.0-safe array_is_list
    if ($isList) { foreach ($j as $g) if (is_array($g)) $out[] = $g; }
    else $out[] = $j;
    return $out;
}
function rc_is_type(array $o, string $type): bool {
    $t = $o['@type'] ?? '';
    return is_array($t) ? in_array($type, $t, true) : $t === $type;
}
// scalar-ify a JSON-LD value that might be a string, a {@value:…}, or an array
function rc_str($v) {
    if (is_string($v)) return $v;
    if (is_array($v)) return isset($v['@value']) ? (string)$v['@value']
        : (isset($v['name']) ? (string)$v['name'] : (string)reset($v));
    return (string)$v;
}
function rc_image($v): string {
    if (is_string($v)) return $v;
    if (is_array($v)) {
        if (isset($v['url'])) return (string)$v['url'];
        foreach ($v as $x) { $u = rc_image($x); if ($u !== '') return $u; }
    }
    return '';
}
// collect step texts from any recipeInstructions shape
function rc_steps($v): array {
    $out = [];
    if (is_string($v)) {
        foreach (preg_split('/\r?\n/', $v) as $line) { $line = trim($line); if ($line !== '') $out[] = $line; }
        return $out;
    }
    if (!is_array($v)) return $out;
    foreach ($v as $step) {
        if (is_string($step)) { $s = trim($step); if ($s !== '') $out[] = $s; continue; }
        if (!is_array($step)) continue;
        if (rc_is_type($step, 'HowToSection') && !empty($step['itemListElement'])) {
            $out = array_merge($out, rc_steps($step['itemListElement']));   // flatten sections
        } elseif (!empty($step['text'])) {
            $s = trim((string)rc_str($step['text'])); if ($s !== '') $out[] = $s;
        } elseif (!empty($step['name'])) {
            $s = trim((string)rc_str($step['name'])); if ($s !== '') $out[] = $s;
        }
    }
    return $out;
}
// ISO-8601 duration (PT1H30M) -> "1 hr 30 min"
function rc_duration(string $iso): string {
    if (!preg_match('/^P(?:\d+D)?T(?:(\d+)H)?(?:(\d+)M)?/', $iso, $m)) return '';
    $parts = [];
    if (!empty($m[1])) $parts[] = (int)$m[1] . ' hr';
    if (!empty($m[2])) $parts[] = (int)$m[2] . ' min';
    return implode(' ', $parts);
}

function extract_readable(string $html, string $baseUrl, string $ctype = ''): array {
    $html = df_to_utf8($html, $ctype);          // normalize Shift-JIS/1251/etc -> UTF-8
    $dom = new DOMDocument();
    libxml_use_internal_errors(true);
    $dom->loadHTML('<?xml encoding="UTF-8" ?>' . $html);
    libxml_clear_errors();
    // A body with no element at all (a bare "<!DOCTYPE html>", a lone comment)
    // parses to a document with no root: every fallback below ends at a null
    // documentElement and render_node(null) is a TypeError -- a 500.
    if ($dom->documentElement === null) return ['', '<p>(no readable text found)</p>', '', ''];
    $xp = new DOMXPath($dom);

    // Title: prefer og:title, BUT if the page's own <h1> is a prefix of it, keep
    // the cleaner h1 — og:title routinely appends " - Sitename" / " | Site" (e.g.
    // og "Duck - Wikipedia" vs h1 "Duck"). Fall back h1 > <title>.
    $title = '';
    if (($t = $xp->query('//title'))->length) $title = trim($t->item(0)->textContent);
    $h1 = '';
    if (($h = $xp->query('//h1'))->length) $h1 = trim($h->item(0)->textContent);
    $ogq = $xp->query('//meta[@property="og:title" or @name="og:title"]/@content');
    $og = $ogq->length ? trim($ogq->item(0)->nodeValue) : '';
    // Several <h1>s (docs pages that number their sections as h1, long essays):
    // the first h1 is just section 1, not the title. Take the h1 the page's own
    // <title>/og:title echoes (longest match), else the <title>/og:title itself;
    // step 1 then drops only that h1 and keeps the others as section headings.
    $h1s = [];
    foreach ($xp->query('//h1') as $hh) {
        $ht = trim(preg_replace('/\s+/u', ' ', $hh->textContent));
        if ($ht !== '') $h1s[] = $ht;
    }
    $multiH1 = count($h1s) > 1;
    if ($multiH1) {
        $ref = $og !== '' ? $og : $title;
        $pick = '';
        foreach ($h1s as $ht) {
            if (mb_stripos($ref, $ht) !== false && mb_strlen($ht) > mb_strlen($pick)) $pick = $ht;
        }
        if ($pick !== '' || $ref !== '') $title = $pick !== '' ? $pick : $ref;
    } elseif ($og !== '') $title = ($h1 !== '' && mb_stripos($og, $h1) === 0) ? $h1 : $og;
    elseif ($h1 !== '')  $title = $h1;

    // honour <base href> so relative links/images resolve correctly
    $b = $xp->query('//base[@href]/@href');
    if ($b->length && trim($b->item(0)->nodeValue) !== '') {
        $baseUrl = absolutize($baseUrl, trim($b->item(0)->nodeValue));
    }

    // detect "next page" / "previous page" links before we strip <link>/<a rel> chrome
    ['next' => $next, 'prev' => $prev] = df_rel_pages($xp);

    // 1. strip junk tags outright (h1 too: we emit the title as the one heading;
    //    with several h1s only the title's own h1 goes, the rest become h2)
    if ($multiH1) {
        foreach (iterator_to_array($xp->query('//h1')) as $hh) {
            $ht = trim(preg_replace('/\s+/u', ' ', $hh->textContent));
            if ($ht === '' || mb_strtolower($ht) === mb_strtolower($title)) { $hh->parentNode->removeChild($hh); continue; }
            $h2 = $dom->createElement('h2');
            foreach (iterator_to_array($hh->attributes) as $at) $h2->setAttribute($at->name, $at->value);
            while ($hh->firstChild) $h2->appendChild($hh->firstChild);
            $hh->parentNode->replaceChild($h2, $hh);
        }
    }
    foreach (['script','style','noscript','nav','header','footer','aside','form','iframe',
              'svg','button','input','select','textarea','link','meta','h1','template'] as $tag) {
        $nodes = $xp->query('//' . $tag);
        for ($i = $nodes->length - 1; $i >= 0; $i--) {
            $n = $nodes->item($i);
            if ($n->parentNode) $n->parentNode->removeChild($n);
        }
    }

    // 2. strip junk by class/id (share bars, comments, cookie banners, wiki chrome...)
    $junkRe = '/\b(comments?|sidebar|share|social|related|promo|advert|ads|sponsor|cookie|banner'
            . '|newsletter|popup|breadcrumbs?|pagination|mw-editsection|navbox|hatnote|catlinks'
            . '|toc|references?|reflist|skip-link|screen-reader)\b/i';
    $bodyNode = $xp->query('//body')->item(0);
    $bodyLen  = $bodyNode ? strlen(trim($bodyNode->textContent)) : 0;
    $doomed = [];
    foreach ($xp->query('//*[@class or @id]') as $el) {
        $sig = $el->getAttribute('class') . ' ' . $el->getAttribute('id');
        $tag = strtolower($el->nodeName);
        if ($tag === 'body' || $tag === 'html' || $tag === 'main' || $tag === 'article') continue;
        if (!preg_match($junkRe, $sig)) continue;
        // Never strip a "junk-classed" element that holds a large share of the page
        // text — it's almost certainly the content with an unlucky class name
        // (e.g. MDN wraps docs in <div class="reference-layout__body">).
        if ($bodyLen > 0 && strlen(trim($el->textContent)) > 0.4 * $bodyLen) continue;
        $doomed[] = $el;
    }
    // A page that is mostly comments (a forum thread, an HN discussion) IS its
    // comments: when the comment-classed blocks together hold over half the
    // page text, keep them. Each one alone is under the 40% guard above, so
    // they were all stripped and a thread rendered as its first post.
    $isCmt = fn(DOMElement $el) => preg_match('/\bcomments?\b/i', $el->getAttribute('class') . ' ' . $el->getAttribute('id')) === 1;
    $cmt = [];
    foreach ($doomed as $el) if ($isCmt($el)) $cmt[spl_object_id($el)] = $el;
    $cmtLen = 0;
    foreach ($cmt as $el) {
        $nested = false;
        for ($pp = $el->parentNode; $pp; $pp = $pp->parentNode) if (isset($cmt[spl_object_id($pp)])) { $nested = true; break; }
        if (!$nested) $cmtLen += strlen(trim($el->textContent));
    }
    if ($bodyLen > 0 && $cmtLen > 0.5 * $bodyLen) {
        $doomed = array_filter($doomed, fn($el) => !isset($cmt[spl_object_id($el)]));
    }
    foreach ($doomed as $el) if ($el->parentNode) $el->parentNode->removeChild($el);

    // 3. scope to semantic containers when present and substantial
    $scope = null;
    foreach (['//main', '//*[@role="main"]', '//article'] as $q) {
        $n = $xp->query($q);
        if ($q === '//article') {
            // several top-level <article>s = a thread or listing (XenForo makes
            // every post an <article>): scope to what holds all of them, not the
            // first post alone
            $tops = [];
            foreach ($n as $ar) {
                if (!$xp->query('ancestor::article', $ar)->length && strlen(trim($ar->textContent)) > 80) $tops[] = $ar;
            }
            if (count($tops) > 1 && ($lca = rd_common_ancestor($tops)) instanceof DOMElement
                && !in_array(strtolower($lca->nodeName), ['html'], true)) { $scope = $lca; break; }
        }
        if ($n->length && strlen(trim($n->item(0)->textContent)) > 400) { $scope = $n->item(0); break; }
    }

    // 4. score candidate containers by text density + class/id hints.
    //    Not just <p>: list pages and reference tables carry their text in
    //    li/td/dd, and a p-only scorer orphans them (learned from Wikipedia lists).
    $cands = [];
    $q = './/p | .//li | .//dd | .//td | .//blockquote | .//pre';
    $ps = $scope ? $xp->query($q, $scope) : $xp->query(str_replace('.//', '//', $q));
    foreach ($ps as $p) {
        $len = strlen(trim($p->textContent));
        if ($len < 25) continue;
        // credit only true containers while climbing -- crediting table innards
        // (tbody/tr) makes them "win" and their rows render wrapperless
        $anc = $p->parentNode; $hops = 0;
        while ($anc instanceof DOMElement && $hops < 6) {
            $atag = strtolower($anc->nodeName);
            if (in_array($atag, ['div', 'article', 'section', 'main', 'body'], true)) {
                $id = spl_object_id($anc);
                if (!isset($cands[$id])) $cands[$id] = ['el' => $anc, 'score' => class_hint($anc)];
                $cands[$id]['score'] += $len + 5;
            }
            $anc = $anc->parentNode; $hops++;
        }
    }

    // 5. among top candidates, penalize link-dense blocks (menus, indexes)
    $best = null;
    if ($cands) {
        usort($cands, fn($a, $b) => $b['score'] <=> $a['score']);
        $bestAdj = -INF;
        foreach (array_slice($cands, 0, 6) as $c) {
            // whitespace-normalised: source indentation inflated the text side and
            // hid link-dense blocks
            $txt = max(1, rd_tlen($c['el']));
            $ltxt = 0;
            foreach ($xp->query('.//a', $c['el']) as $a) $ltxt += rd_tlen($a);
            $adj = $c['score'] * (1 - 0.8 * min(1, $ltxt / $txt));
            if ($adj > $bestAdj) { $bestAdj = $adj; $best = $c['el']; }
        }
    }
    if (!$best) $best = $scope;
    if (!$best) {
        $body = $xp->query('//body');
        $best = $body->length ? $body->item(0) : $dom->documentElement;
    }

    // coverage guard: if the winner holds <25% of the (junk-stripped) page text,
    // we picked a fragment -- widen to the semantic scope / body instead
    $wide = $scope;
    if (!$wide) { $b = $xp->query('//body'); $wide = $b->length ? $b->item(0) : $dom->documentElement; }
    $total = strlen(trim($wide->textContent));
    if ($total > 0 && strlen(trim($best->textContent)) < 0.25 * $total) $best = $wide;

    // in-page links (footnotes, tables of contents): ids that are both linked
    // to and present in what we render stay jumpable (href="#x" + <a name="x">)
    $linked = [];
    foreach ($xp->query('//a[starts-with(@href,"#")]/@href') as $hr) {
        $frag = rawurldecode(substr($hr->nodeValue, 1));
        if ($frag !== '') $linked[$frag] = true;
    }
    $present = [];
    if ($linked) {
        foreach ($xp->query('.//*[@id] | .//a[@name]', $best) as $el) {
            foreach ([$el->getAttribute('id'), $el->getAttribute('name')] as $k) if ($k !== '' && isset($linked[$k])) $present[$k] = true;
        }
        if ($best instanceof DOMElement) {
            foreach ([$best->getAttribute('id'), $best->getAttribute('name')] as $k) if ($k !== '' && isset($linked[$k])) $present[$k] = true;
        }
    }
    rd_anchor_targets($present);
    $out = render_node($best, $baseUrl);
    if (trim(strip_tags($out)) === '') {
        $body = $xp->query('//body');
        $out = $body->length ? render_node($body->item(0), $baseUrl) : '<p>(no readable text found)</p>';
    }
    rd_anchor_targets([]);
    $out = rd_tidy_ws($out);
    // tidy: collapse <br> runs, drop empty paragraphs, pad empty table cells
    // (empty <td> renders borderless on Netscape-era engines -- classic fix is &nbsp;)
    $out = preg_replace('#(<br>\s*){3,}#i', '<br><br>', $out);
    // adjacent inline links (nav/button rows) have no whitespace between them in
    // source -> "LinkALinkB"; separate them and any link glued to a following word
    $out = preg_replace('#</a>\s*<a\b#i', '</a> <a', $out);
    $out = preg_replace('#(?<!">)</a>(?=[A-Z0-9])#', '</a> ', $out);   // not after an empty <a name="x"></a>
    $out = preg_replace('#<p>\s*</p>#i', '', $out);
    $out = preg_replace('#<caption>\s*</caption>#i', '', $out);
    $out = preg_replace('#<(td|th)([^>]*)>\s*</\1>#i', '<$1$2>&nbsp;</$1>', $out);
    return [$title, ascii_html($out), $next, $prev];
}

// ---------------------------------------------------------------------------
// ORIGINAL-LAYOUT MODE
// Instead of extracting "the article", pass the page through mostly intact so
// era-appropriate pages (tables, <font>, image nav) render as designed on a
// vintage browser. Security: we keep a broad set of *presentational* tags but
// allow only an allowlist of *attributes* (no on*, no style, no javascript:/
// data: URLs) and route links/images through the reader's own proxies.
// ---------------------------------------------------------------------------
function render_original(string $html, string $baseUrl, string $ctype = ''): array {
    $html = df_to_utf8($html, $ctype);
    $dom = new DOMDocument();
    libxml_use_internal_errors(true);
    $dom->loadHTML('<?xml encoding="UTF-8" ?>' . $html);
    libxml_clear_errors();
    if ($dom->documentElement === null) return ['', '<p>(no readable text found)</p>'];   // see extract_readable
    $xp = new DOMXPath($dom);

    $title = '';
    if (($t = $xp->query('//title'))->length) $title = trim($t->item(0)->textContent);

    $b = $xp->query('//base[@href]/@href');
    if ($b->length && trim($b->item(0)->nodeValue) !== '') {
        $baseUrl = absolutize($baseUrl, trim($b->item(0)->nodeValue));
    }

    // remove executable / non-rendering elements entirely (with their subtrees)
    foreach (['script','style','noscript','iframe','frame','frameset','object','embed',
              'applet','form','input','button','select','textarea','link','meta','base',
              'title','head','svg','math','template','param','source','track','canvas',
              'audio','video'] as $tag) {
        $ns = $xp->query('//' . $tag);
        for ($i = $ns->length - 1; $i >= 0; $i--) {
            $n = $ns->item($i);
            if ($n->parentNode) $n->parentNode->removeChild($n);
        }
    }

    $body = $xp->query('//body')->item(0) ?? $dom->documentElement;
    return [$title, ascii_html(sanitize_node($body, $baseUrl))];
}

function sanitize_node(DOMNode $node, string $baseUrl): string {
    if ($node->nodeType === XML_TEXT_NODE) return htmlspecialchars($node->textContent, ENT_QUOTES, 'UTF-8');
    if ($node->nodeType !== XML_ELEMENT_NODE) return '';
    $tag = strtolower($node->nodeName);

    // presentational/structural tags we preserve; anything else -> drop tag, keep text
    static $keep = ['body','table','thead','tbody','tfoot','tr','td','th','caption','col','colgroup',
                    'div','span','center','font','p','br','hr','b','i','u','em','strong','a','img',
                    'ul','ol','li','dl','dt','dd','h1','h2','h3','h4','h5','h6','blockquote','pre',
                    'tt','code','kbd','samp','var','small','big','sub','sup','strike','s','nobr',
                    'address','cite','q','abbr','acronym','dfn','ins','del','bdo','wbr','menu','dir'];
    static $void = ['br','hr'];

    if ($tag === 'img') {
        $src = $node->getAttribute('src');
        if ($src === '' || strpos($src, 'data:') === 0) {
            foreach (['data-src', 'data-original', 'data-lazy-src'] as $la) {
                if ($node->getAttribute($la) !== '') { $src = $node->getAttribute($la); break; }
            }
        }
        if ($src === '' || strpos($src, 'data:') === 0) return '';
        $abs = absolutize($baseUrl, $src);
        if (!preg_match('#^https?://#i', $abs)) return '';
        if (DF_IMGMODE === 'ascii') return df_ascii_raw_img($node, $abs);
        $q = DF_IMGMODE !== 'color' ? '&amp;im=' . DF_IMGMODE : '';
        if (DF_YEAR !== '') $q .= '&amp;year=' . DF_YEAR;
        return '<img src="/img.php?url=' . htmlspecialchars(urlencode($abs), ENT_QUOTES) . $q . '"'
             . safe_attrs($node, ['alt','width','height','border','hspace','vspace','align']) . '>';
    }

    $inner = '';
    foreach ($node->childNodes as $c) $inner .= sanitize_node($c, $baseUrl);

    if ($tag === 'a') {
        $abs = absolutize($baseUrl, $node->getAttribute('href'));
        if ($node->getAttribute('href') === '' || !preg_match('#^https?://#i', $abs)) return $inner;
        if (df_is_download($abs)) {   // binary/archive -> download proxy, not the reader
            return rd_link('<a href="/dl.php?url=' . htmlspecialchars(urlencode($abs), ENT_QUOTES) . '">', $inner);
        }
        $q = (DF_IMAGES ? '' : '&amp;img=0') . (DF_IMGMODE !== 'color' ? '&amp;im=' . DF_IMGMODE : '')
           . (DF_YEAR !== '' ? '&amp;year=' . DF_YEAR : '') . '&amp;raw=1';
        // signed (lib.php df_readtok): following a link from a page being read
        // skips the hourly read budget like a search result does (2026-11-12)
        return rd_link('<a href="/read.php?url=' . htmlspecialchars(urlencode($abs), ENT_QUOTES) . $q
                       . df_readtok_qs($abs, true) . '">', $inner);
    }

    if (!in_array($tag, $keep, true)) return $inner . ' ';         // drop tag, keep contents
    if (in_array($tag, $void, true)) return "<$tag>";
    return '<' . $tag . safe_attrs($node) . '>' . $inner . '</' . $tag . '>';
}

// Original-layout mode, ascii images: an image whose declared size is small
// (spacers, bullets, nav buttons -- old table layouts are full of them) shows
// only its alt text, as Lynx itself would show it, and spends none of the
// page's art budget; anything else becomes art, or its fallback text.
function df_ascii_raw_img(DOMElement $node, string $abs): string {
    $alt = trim($node->getAttribute('alt'));
    $w = (int)$node->getAttribute('width'); $h = (int)$node->getAttribute('height');
    if (($w > 0 && $w < 48) || ($h > 0 && $h < 48)) return $alt !== '' ? '[' . e($alt) . ']' : '';
    $art = df_ascii_inline($abs, DF_YEAR);
    if ($art === '') return '';
    return $art ?? df_ascii_fallback($abs, $alt, !df_in_link($node));
}

// Close a rewritten link. In ascii mode any art inside it is lifted out
// first (df_ascii_hoist); every other mode is byte-for-byte unchanged.
function rd_link(string $open, string $inner): string {
    return DF_IMGMODE === 'ascii' ? df_ascii_hoist($open, $inner) : $open . $inner . '</a>';
}

// Emit only allowlisted presentational attributes, values stripped of anything
// that could break out of the attribute or carry script.
function safe_attrs(DOMElement $el, ?array $only = null): string {
    static $safe = ['align','valign','width','height','bgcolor','color','size','face','border',
                    'cellpadding','cellspacing','colspan','rowspan','nowrap','hspace','vspace',
                    'alt','title','start','clear','noshade','compact','dir','frame','rules',
                    'bordercolor','type','span','char','charoff','abbr','headers','scope'];
    $out = '';
    foreach ($el->attributes as $a) {
        $n = strtolower($a->name);
        if (!in_array($n, $safe, true)) continue;
        if ($only !== null && !in_array($n, $only, true)) continue;
        $v = str_replace(['"', '<', '>', '`'], '', $a->value);       // no attribute break-out
        $out .= ' ' . $n . '="' . htmlspecialchars($v, ENT_QUOTES) . '"';
    }
    return $out;
}

// Pick a srcset candidate near the reader's downscale width — avoids grabbing a
// 1px placeholder or a needlessly huge original.
function df_pick_srcset(string $srcset, int $target = 480): string {
    $cands = [];
    foreach (explode(',', $srcset) as $c) {
        $p = preg_split('/\s+/', trim($c));
        if (empty($p[0])) continue;
        $w = 0;
        if (!empty($p[1])) {
            if (preg_match('/^(\d+)w$/', $p[1], $m))        $w = (int)$m[1];
            elseif (preg_match('/^([\d.]+)x$/', $p[1], $m)) $w = (int)round((float)$m[1] * $target);
        }
        $cands[] = ['u' => $p[0], 'w' => $w];
    }
    if (!$cands) return '';
    $ge = array_values(array_filter($cands, fn($c) => $c['w'] >= $target));   // smallest >= target
    if ($ge) { usort($ge, fn($a, $b) => $a['w'] <=> $b['w']); return $ge[0]['u']; }
    usort($cands, fn($a, $b) => $b['w'] <=> $a['w']);                         // else the largest
    return $cands[0]['u'];
}

function class_hint(DOMElement $el): int {
    $sig = strtolower($el->getAttribute('class') . ' ' . $el->getAttribute('id'));
    $bonus = 0;
    if (preg_match('/\b(article|content|post|entry|main|story|text|body|page)\b/', $sig)) $bonus += 30;
    if (preg_match('/\b(sidebar|footer|nav|menu|widget|meta|caption|byline|tags)\b/', $sig)) $bonus -= 40;
    return $bonus;
}

// Serialize a DOM subtree to a whitelist of tags; links go back through the
// reader, images through the downscaling GIF proxy.
function render_node(DOMNode $node, string $baseUrl): string {
    static $allowed = ['p','br','h1','h2','h3','h4','h5','h6','ul','ol','li','blockquote',
                       'pre','b','i','strong','em','a','hr','table','tr','td','th','code',
                       'dl','dt','dd','sub','sup','caption'];
    static $imgCount = 0;
    if ($node->nodeType === XML_TEXT_NODE) return htmlspecialchars($node->textContent, ENT_QUOTES, 'UTF-8');
    if ($node->nodeType !== XML_ELEMENT_NODE) return '';

    $tag = strtolower($node->nodeName);
    if ($tag === 'img') {
        $alt = trim($node->getAttribute('alt'));
        $altHtml = $alt !== '' ? ' [img: ' . htmlspecialchars($alt, ENT_QUOTES) . '] ' : '';
        if (!DF_IMAGES) return $altHtml;
        // Skip decorative/avatar images entirely — and DON'T count them against
        // the budget, so a forum/Q&A page's real diagrams aren't starved out by
        // 20 gravatars (a StackOverflow answer page was dropping content figures
        // to placeholders while avatars ate the 25 slots).
        $rawSrc = $node->getAttribute('src') . ' ' . $node->getAttribute('data-src');
        $w = (int)$node->getAttribute('width'); $h = (int)$node->getAttribute('height');
        if (preg_match('/\buser avatar\b|\bavatar\b|\bgravatar\b|\bidenticon\b/i', $alt . ' ' . $rawSrc)
            || preg_match('/[?&](s|sz|size)=\d{1,2}\b|=s\d{1,2}(-|\b)/', $rawSrc)   // ?s=64 / =s48-
            || ($w > 0 && $w <= 48) || ($h > 0 && $h <= 48)) {
            return '';                      // decorative — drop silently, don't spend the budget
        }
        if ($imgCount >= 25) return $altHtml;          // spare 20-year-old CPUs a 100-image page
        $src = $node->getAttribute('src');
        // sites often put a placeholder in src and the real image in a lazy attr
        if ($src === '' || strpos($src, 'data:') === 0) {
            foreach (['data-src', 'data-lazy-src', 'data-original'] as $la) {
                if ($node->getAttribute($la) !== '') { $src = $node->getAttribute($la); break; }
            }
        }
        // srcset: pick a candidate near our downscale width, not the smallest
        if ($src === '' || strpos($src, 'data:') === 0) {
            $ss = $node->getAttribute('srcset') ?: $node->getAttribute('data-srcset');
            if ($ss !== '') $src = df_pick_srcset($ss);
        }
        if ($src === '' || strpos($src, 'data:') === 0) return $altHtml;
        // skip tracking pixels / spacers
        $w = (int)$node->getAttribute('width'); $h = (int)$node->getAttribute('height');
        if (($w > 0 && $w < 8) || ($h > 0 && $h < 8)) return '';
        $abs = absolutize($baseUrl, $src);
        if (!preg_match('#^https?://#i', $abs)) return $altHtml;
        $imgCount++;
        // surface alt text as a visible caption -- it's written for accessibility,
        // and on a downscaled GIF it doubles as the figure caption
        // ...unless the image sits in a <figure> with its own <figcaption>, which
        // renders as the caption instead (no doubled caption)
        $cap = (strlen($alt) > 3 && !rd_in_captioned_figure($node))
             ? '<br><font size="1"><i>' . htmlspecialchars($alt, ENT_QUOTES) . '</i></font>' : '';
        if (DF_IMGMODE === 'ascii') {
            $art = df_ascii_inline($abs, DF_YEAR);
            if ($art === '') return '';                     // spacer/pixel, nothing to show
            // the art is its own block, so the caption drops its leading <br>
            return $art !== null ? $art . ($cap !== '' ? substr($cap, 4) . '<br>' : '')
                                 : ' ' . df_ascii_fallback($abs, $alt, !df_in_link($node)) . ' ';
        }
        $mode = DF_IMGMODE !== 'color' ? '&amp;im=' . DF_IMGMODE : '';
        if (DF_YEAR !== '') $mode .= '&amp;year=' . DF_YEAR;   // pull era-correct image from Wayback
        return '<br><img src="/img.php?url=' . htmlspecialchars(urlencode($abs), ENT_QUOTES) . $mode
             . '" alt="' . htmlspecialchars($alt, ENT_QUOTES) . '" border="0">' . $cap . '<br>';
    }

    $inner = '';
    foreach ($node->childNodes as $c) $inner .= render_node($c, $baseUrl);
    // an element an in-page link points at gets a named anchor in front of it
    $nm = rd_anchor_for($node);

    if ($tag === 'figure') return $nm . '<p>' . trim($inner) . '</p>';
    if ($tag === 'figcaption') {
        $t = trim($inner);
        return $t === '' ? $nm : $nm . '<br><font size="1"><i>' . $t . '</i></font>';
    }
    if ($tag === 'a') {
        $href = $node->getAttribute('href');
        if ($href !== '' && $href[0] === '#') {
            // in-page link: local jump when the target is on the rendered page,
            // else plain text (never a reload of the whole page through the proxy)
            $frag = rawurldecode(substr($href, 1));
            if ($frag !== '' && trim($inner) !== '' && isset(rd_anchor_targets()[$frag])) {
                return $nm . '<a href="#' . htmlspecialchars(rawurlencode($frag), ENT_QUOTES) . '">' . $inner . '</a>';
            }
            return $nm . $inner;
        }
        if ($href === '' || trim($inner) === '') return $nm . $inner;
        $abs = absolutize($baseUrl, $href);
        if (!preg_match('#^https?://#i', $abs)) return $inner;
        if (df_is_download($abs)) {   // binary/archive -> download proxy, not the reader
            return rd_link('<a href="/dl.php?url=' . htmlspecialchars(urlencode($abs), ENT_QUOTES) . '">', $inner);
        }
        $imgParam = DF_IMAGES ? '' : '&amp;img=0';
        if (DF_IMGMODE !== 'color') $imgParam .= '&amp;im=' . DF_IMGMODE;   // persist colour mode
        if (DF_YEAR !== '') {
            // in Wayback mode 'year' flips the default to original layout, so
            // reader-mode links must carry raw=0; on live pages reader is already
            // the default and raw=0 is dead weight on every link (~32% of a
            // link-dense article's bytes)
            $imgParam .= '&amp;year=' . DF_YEAR . '&amp;raw=0';
        }
        return rd_link('<a href="/read.php?url=' . htmlspecialchars(urlencode($abs), ENT_QUOTES) . $imgParam
                       . df_readtok_qs($abs, true) . '">', $inner);   // signed, as above
    }
    if (!in_array($tag, $allowed, true)) {
        // Drop the tag, keep its text. Add a separating space UNLESS the tag is a
        // known inline element -- so block wrappers AND custom web-component tags
        // (<blz-button>, <my-card>, anything hyphenated) don't glue adjacent text
        // together, while real inline markup (<span>, <font>) keeps words intact.
        static $inline = ['span','font','small','label','abbr','cite','q','mark','u','s',
                          'strike','tt','big','wbr','bdi','bdo','ins','del','time','data',
                          'output','kbd','samp','var','ruby','rt','rp','nobr','acronym'];
        if (rd_in_pre($node)) {
            // code highlighters put each line in a block <div>/<span class="line">:
            // end such a line with a newline, and never pad with a space inside <pre>
            $line = !in_array($tag, $inline, true)
                 || ($tag === 'span' && (preg_match('/display\s*:\s*block/i', $node->getAttribute('style'))
                     || preg_match('/(^|\s)(line|token-line|cm-line|ec-line|code-line)(\s|$)/', $node->getAttribute('class'))));
            return $nm . (($line && $inner !== '' && substr($inner, -1) !== "\n" && substr($inner, -4) !== '<br>') ? $inner . "\n" : $inner);
        }
        if (!in_array($tag, $inline, true) && !in_array($tag, ['html', 'body', 'tbody', 'thead', 'tfoot', 'picture', 'center'], true)
            && rd_inline_only($inner) && !rd_in_inline_context($node)) {
            // a block wrapper holding only inline content is a paragraph in all
            // but name (forums and many CMSs never use <p>): give it one, or a
            // line break inside a list item / table cell
            $pt = $node->parentNode ? strtolower($node->parentNode->nodeName) : '';
            return $nm . (in_array($pt, ['li', 'td', 'th', 'dd', 'blockquote'], true)
                ? trim($inner) . '<br>' : '<p>' . trim($inner) . '</p>') . "\n";
        }
        return $nm . (in_array($tag, $inline, true) ? $inner : $inner . ' ');
    }
    if ($tag === 'br' || $tag === 'hr') return $nm . "<$tag>";
    if ($tag === 'table') return $nm . '<table border="1" cellpadding="3" cellspacing="0">' . $inner . '</table>';
    if ($tag === 'td' || $tag === 'th') {                        // keep spans or the grid shears
        $attrs = '';
        foreach (['colspan', 'rowspan'] as $at) {
            $v = (int)$node->getAttribute($at);
            if ($v > 1) $attrs .= ' ' . $at . '="' . $v . '"';
        }
        return "<$tag$attrs>" . $nm . $inner . "</$tag>";
    }
    // the anchor goes inside list items / rows (only cells may hold it there)
    // and in front of everything else
    if (in_array($tag, ['li', 'dt', 'dd', 'caption'], true)) return "<$tag>" . $nm . $inner . "</$tag>";
    if ($tag === 'tr') return "<$tag>" . $inner . "</$tag>";
    return $nm . "<$tag>" . $inner . "</$tag>";
}

// --- reader helpers (2026-11-12) ---------------------------------------------

// Whitespace-normalised text length (source indentation is not text).
function rd_tlen(DOMNode $n): int {
    return strlen(trim(preg_replace('/\s+/u', ' ', $n->textContent) ?? ''));
}

// Lowest common ancestor of several nodes (null if none).
function rd_common_ancestor(array $nodes): ?DOMNode {
    $paths = [];
    foreach ($nodes as $nd) {
        $p = [];
        for ($a = $nd->parentNode; $a; $a = $a->parentNode) array_unshift($p, $a);
        $paths[] = $p;
    }
    $lca = null;
    for ($i = 0; ; $i++) {
        $c = $paths[0][$i] ?? null;
        if ($c === null) break;
        foreach ($paths as $p) if (($p[$i] ?? null) !== $c) break 2;
        $lca = $c;
    }
    return $lca;
}

// The ids in-page links may jump to during the current render (set by
// extract_readable around render_node; [] otherwise).
function rd_anchor_targets(?array $set = null): array {
    static $t = [];
    if ($set !== null) $t = $set;
    return $t;
}
function rd_anchor_for(DOMNode $node): string {
    if (!($node instanceof DOMElement)) return '';
    $t = rd_anchor_targets();
    if (!$t) return '';
    $out = '';
    foreach (array_unique([$node->getAttribute('id'), strtolower($node->nodeName) === 'a' ? $node->getAttribute('name') : '']) as $k) {
        if ($k !== '' && isset($t[$k])) $out .= '<a name="' . htmlspecialchars($k, ENT_QUOTES) . '"></a>';
    }
    return $out;
}

function rd_in_pre(DOMNode $node): bool {
    for ($p = $node->parentNode; $p; $p = $p->parentNode) if (strtolower($p->nodeName) === 'pre') return true;
    return false;
}

// Inside an element where a <p> would be wrong (a link, a heading, ...).
function rd_in_inline_context(DOMNode $node): bool {
    static $ctx = ['p', 'a', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'pre', 'dt', 'caption', 'figcaption',
                   'b', 'i', 'strong', 'em', 'code', 'span', 'font', 'small', 'label', 'button', 'th'];
    for ($p = $node->parentNode; $p; $p = $p->parentNode) if (in_array(strtolower($p->nodeName), $ctx, true)) return true;
    return false;
}

// Rendered HTML that is inline only: some text or an image, and no block tag.
function rd_inline_only(string $html): bool {
    if (trim(strip_tags($html, '<img>')) === '') return false;
    return !preg_match('#<(p|h[1-6]|ul|ol|li|table|tr|td|th|pre|blockquote|dl|dt|dd|hr|caption)\b#i', $html)
        && !preg_match('#<br>\s*<img\b#i', $html);     // a reader image is its own block
}

// An <img> inside a <figure> that has its own <figcaption>.
function rd_in_captioned_figure(DOMNode $node): bool {
    for ($p = $node->parentNode; $p; $p = $p->parentNode) {
        if (strtolower($p->nodeName) === 'figure') return $p instanceof DOMElement && $p->getElementsByTagName('figcaption')->length > 0;
    }
    return false;
}

// Collapse whitespace outside <pre>, and hard-wrap <pre> lines at 76 columns
// (a 300-column line widens the 600px layout table into horizontal scrolling).
function rd_tidy_ws(string $out): string {
    $parts = preg_split('#(<pre\b.*?</pre>)#is', $out, -1, PREG_SPLIT_DELIM_CAPTURE);
    $res = '';
    foreach ($parts as $i => $pt) {
        $res .= $i % 2 ? rd_wrap_pre($pt, 76)
                       : preg_replace('/[ \t]*\n\s*/', "\n", preg_replace('/[ \t]+/', ' ', $pt));
    }
    return $res;
}
function rd_wrap_pre(string $pre, int $cols): string {
    $lines = explode("\n", $pre);
    foreach ($lines as &$ln) {
        $vis = 0; $buf = '';
        // tokens: tags (zero width), entities (one column), single characters
        foreach (preg_split('/(<[^>]*>|&#?[a-z0-9]+;)/i', $ln, -1, PREG_SPLIT_DELIM_CAPTURE | PREG_SPLIT_NO_EMPTY) as $tok) {
            if ($tok[0] === '<') { $buf .= $tok; if (preg_match('#^<br\b#i', $tok)) $vis = 0; continue; }   // <br> ends a line too
            if ($tok[0] === '&' && substr($tok, -1) === ';' && strlen($tok) > 2) {
                if ($vis >= $cols) { $buf .= "\n"; $vis = 0; }
                $buf .= $tok; $vis++; continue;
            }
            foreach (preg_split('//u', $tok, -1, PREG_SPLIT_NO_EMPTY) as $ch) {
                if ($vis >= $cols) { $buf .= "\n"; $vis = 0; }
                $buf .= $ch; $vis++;
            }
        }
        $ln = $buf;
    }
    return implode("\n", $lines);
}
