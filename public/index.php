<?php
require __DIR__ . '/lib.php';
header('Content-Type: text/html; charset=iso-8859-1');

// Site-wide floor for cheap pages: counts the landing page and every bang
// redirect, which otherwise exit before the 'search' bucket below. A real
// search costs one 'page' + one 'search' hit (see 'page' in config.example.php).
if (!df_rate('page')) df_rate_block();

$q = df_input('q');

// "!" or "!help" -> show the homepage with the full shortcuts panel expanded
$help = ($q === '!' || strtolower($q) === '!help');
if ($help) $q = '';

// #12 bang shortcuts: !w term -> Wikipedia reader, !wb url [year] -> Wayback,
// !r url -> read a page directly. Redirect (303) so it works on ancient browsers.
if ($q !== '' && $q[0] === '!') {
    $parts = preg_split('/\s+/', $q, 2);
    $bang  = strtolower(ltrim($parts[0], '!'));
    $rest  = trim($parts[1] ?? '');
    $go = null;
    if (($bang === 'w' || $bang === 'wiki') && $rest !== '') {
        // wiki.php (clean REST summary + opensearch fuzzy-match) replaces the
        // old route-through-read.php's-generic-extractor approach -- same
        // bang, better destination, same reasoning as the page's own header.
        $go = '/wiki.php?q=' . urlencode($rest);
    } elseif ($bang === 'wb' && $rest !== '') {
        $a = preg_split('/\s+/', $rest);
        $yr = (isset($a[count($a) - 1]) && preg_match('/^\d{4}$/', $a[count($a) - 1])) ? array_pop($a) : '';
        $tgt = implode(' ', $a);
        if (!preg_match('#^https?://#i', $tgt)) $tgt = 'https://' . $tgt;
        $go = '/read.php?url=' . urlencode($tgt) . ($yr !== '' ? '&year=' . $yr : '');
    } elseif (($bang === 'r' || $bang === 'read') && $rest !== '') {
        if (!preg_match('#^https?://#i', $rest)) $rest = 'https://' . $rest;
        $go = '/read.php?url=' . urlencode($rest);
    } elseif ($bang === 'pdf' && $rest !== '') {
        if (!preg_match('#^https?://#i', $rest)) $rest = 'https://' . $rest;
        $go = '/pdf.php?url=' . urlencode($rest);
    } elseif (($bang === 'dl' || $bang === 'download' || $bang === 'get') && $rest !== '') {
        if (!preg_match('#^https?://#i', $rest)) $rest = 'https://' . $rest;
        $go = '/dl.php?url=' . urlencode($rest);
    } elseif ($bang === 'watch' && $rest !== '') {
        if (!preg_match('#^https?://#i', $rest)) $rest = 'https://' . $rest;
        $go = '/watch.php?url=' . urlencode($rest);
    } elseif (($bang === 'ytsearch' || $bang === 'yt') && $rest !== '') {
        $go = '/ytsearch.php?q=' . urlencode($rest);
    } elseif ($bang === 'news') {
        $go = '/news.php';
    } elseif ($bang === 'feeds') {
        $go = '/feeds.php';
    } elseif ($bang === 'hn' || $bang === 'hackernews') {
        $go = $rest !== '' && ctype_digit($rest) ? '/hn.php?id=' . $rest : '/hn.php';
    } elseif (($bang === 'weather' || $bang === 'wx') && $rest !== '') {
        $go = '/weather.php?q=' . urlencode($rest);
    } elseif ($bang === 'map' && $rest !== '') {
        $go = '/map.php?q=' . urlencode($rest);
    } elseif (($bang === 'calc' || $bang === 'convert' || $bang === 'conv') && $rest !== '') {
        $go = '/calc.php?q=' . urlencode($rest);
    } elseif (($bang === 'translate' || $bang === 'tr') && $rest !== '') {
        $go = '/translate.php?q=' . urlencode($rest);
    } elseif (($bang === 'ebook' || $bang === 'book') && $rest !== '') {
        $go = '/ebook.php?q=' . urlencode($rest);
    } elseif ($bang === 'wiby' && $rest !== '') {
        $go = '/wiby.php?q=' . urlencode($rest);
    } elseif ($bang === 'surprise') {
        $go = '/wiby.php?surprise=1';
    } elseif ($bang === 'gopher' && $rest !== '') {
        if (!preg_match('#^gopher://#i', $rest)) $rest = 'gopher://' . $rest;
        $go = '/gopher.php?url=' . urlencode($rest);
    } elseif ($bang === 'ftp' && $rest !== '') {
        if (!preg_match('#^ftp://#i', $rest)) $rest = 'ftp://' . $rest;
        $go = '/ftp.php?url=' . urlencode($rest);
    } elseif (($bang === 'dir' || $bang === 'directions') && $rest !== '') {
        $p2 = preg_split('/\s+to\s+/i', $rest, 2);
        $go = count($p2) === 2
            ? '/map.php?from=' . urlencode(trim($p2[0])) . '&to=' . urlencode(trim($p2[1]))
            : '/map.php?q=' . urlencode($rest);
    } elseif (($bang === 'define' || $bang === 'def' || $bang === 'd') && $rest !== '') {
        $go = '/define.php?q=' . urlencode($rest);
    } elseif ($bang === 'ai' && $rest !== '') {
        $go = '/ask.php?q=' . urlencode($rest);
    }
    // A bang with nothing after it ("!weather") used to fall through to an empty
    // search, i.e. the home page with no word of explanation (2026-11-12): send
    // it to that tool's own landing page instead.
    if ($go === null && $rest === '') $go = bang_landing($bang);
    if ($go !== null) { header('Location: ' . $go, true, 302); exit; }   // 302 = widest old-browser support
    // unknown bang -> drop the "!tag" and just search the remaining words
    $q = $rest;
}

if ($q === '') {
    echo page_head(DUCKFIND_NAME . ' - browse the modern web on vintage computers', false,
        DUCKFIND_NAME . ' serves the modern, JavaScript-heavy web as clean HTML for old '
        . 'browsers: search, read articles, maps, news, PDFs and more on a System 7 Mac, '
        . 'Windows 3.1, or any vintage machine. A self-hosted, privacy-first FrogFind-style proxy.');
    echo '<center>' . "\n";
    echo '<table width="460" border="0" cellpadding="0" cellspacing="0"><tr><td align="center">' . "\n";

    // masthead
    echo '<br><img src="/duck.gif?v=4" alt="[DuckFind]" width="128" height="120" border="0"><br>' . "\n";
    echo '<font size="6"><b>Duck<font color="#E88C22">Find</font></b></font><br>' . "\n";
    echo '<font size="2"><i>the modern web, in plain HTML -- for vintage computers</i></font>' . "\n";

    // primary search
    echo '<br><br>' . "\n";
    echo '<form action="/" method="get">' . "\n";
    echo '<input type="text" name="q" size="38">&nbsp;<input type="submit" value="Quack!">' . "\n";
    echo '</form>' . "\n";
    // the shortcuts link toggles: when the panel is open it links back to the
    // plain homepage (a no-JS "collapse"); otherwise it opens the panel.
    $shortcuts = $help ? '<a href="/"><b>shortcuts</b></a>' : '<a href="/?q=!help">shortcuts</a>';
    echo '<font size="1"><a href="/news.php">news</a> &nbsp;&middot;&nbsp; '
       . '<a href="/feeds.php">my feeds</a> &nbsp;&middot;&nbsp; '
       . '<a href="/map.php">maps</a> &nbsp;&middot;&nbsp; '
       . '<a href="/read.php">reader</a> &nbsp;&middot;&nbsp; '
       . '<a href="/guestbook.php">guestbook</a> &nbsp;&middot;&nbsp; '
       . $shortcuts . '</font>' . "\n";

    // expandable shortcut panel (shown on !help)
    if ($help) {
        echo '<br><br><table width="400" border="1" cellpadding="4" cellspacing="0"><tr><td>' . "\n";
        echo '<font size="2"><b>Search shortcuts</b> '
           . '<font size="1">[<a href="/">hide</a>]</font> -- type in the box above:<br>' . "\n";
        if (df_cfg('ai_api_key', '') !== '')
            echo '<tt>!ai</tt> <i>question</i> -- get an AI answer<br>' . "\n";
        echo '<tt>!w</tt> <i>term</i> -- jump to a Wikipedia article<br>' . "\n";
        echo '<tt>!wb</tt> <i>url</i> [<i>year</i>] -- read a Wayback Machine copy<br>' . "\n";
        echo '<tt>!r</tt> <i>url</i> -- read any page directly<br>' . "\n";
        echo '<tt>!pdf</tt> <i>url</i> -- read a PDF as HTML or page images<br>' . "\n";
        echo '<tt>!dl</tt> <i>url</i> -- download a file over plain HTTP<br>' . "\n";
        if (trim((string)df_cfg('relay_url', '')) !== '')
            echo '<tt>!watch</tt> <i>youtube url</i> -- watch a video, converted for old machines<br>' . "\n"
               . '<tt>!ytsearch</tt> <i>term</i> -- search YouTube, click a result to watch<br>' . "\n";
        echo '<tt>!hn</tt> -- Hacker News + comment threads<br>' . "\n";
        echo '<tt>!weather</tt> <i>place</i> -- 5-day forecast<br>' . "\n";
        echo '<tt>!map</tt> <i>place</i> -- street map, pan &amp; zoom<br>' . "\n";
        echo '<tt>!dir</tt> <i>a</i> to <i>b</i> -- driving directions<br>' . "\n";
        echo '<tt>!gopher</tt> <i>host</i> -- browse gopherspace<br>' . "\n";
        echo '<tt>!ftp</tt> <i>host</i> -- browse or download from anonymous FTP<br>' . "\n";
        echo '<tt>!ebook</tt> <i>title or author</i> -- search &amp; read free Project Gutenberg books<br>' . "\n";
        echo '<tt>!wiby</tt> <i>term</i> -- search the classic web (Wiby)<br>' . "\n";
        echo '<tt>!surprise</tt> -- a random classic page<br>' . "\n";
        echo '<tt>!translate</tt> <i>text</i> to <i>language</i> -- translator<br>' . "\n";
        echo '<tt>!calc</tt> <i>2+2*7</i> -- calculator<br>' . "\n";
        echo '<tt>!convert</tt> <i>5 mi to km</i> -- units &amp; currency<br>' . "\n";
        echo '<tt>!define</tt> <i>word</i> -- dictionary lookup<br>' . "\n";
        echo '<tt>!news</tt> -- jump to the news portal<br>' . "\n";
        echo '<tt>!feeds</tt> -- your personal feed reader</font>' . "\n";
        echo '</td></tr></table>' . "\n";
    }

    echo '</td></tr></table>' . "\n";
    echo '</center>' . "\n";
    echo page_foot(false, false);   // tagline and nav row already said once above
    exit;
}

if (!df_rate('search')) df_rate_block();
$s   = max(0, (int)($_GET['s'] ?? 0));           // result offset for pagination
$ddg = 'https://html.duckduckgo.com/html/?q=' . urlencode($q) . ($s > 0 ? '&s=' . $s : '');

// Outbound DuckDuckGo requests are guarded three ways (lib.php): only cache
// misses count; each one takes a unit of the site-wide hourly and daily caps
// (per-IP limits don't stop a botnet, and enough scraped searches get our IP
// flagged -- killing search for everyone); and an endpoint that answered with
// a block is left alone for its backoff period (60 s -> 5 min -> 15 min).
// html is tried first; DuckDuckGo Lite is the fallback when html is backing
// off, blocked, or unreadable (first page only -- lite pages with POSTed forms
// (s/dc/vqd tokens), so a "more results" link can't be built from a GET, and an
// html offset (?s=) has no lite equivalent). Lite is only tried when it is not
// in its own backoff, so under a full block steady state is ~0 DDG requests.
// Counters are aggregate daily totals only: ddgblocked/ddgmarkup = html answer
// unusable, ddglite = fallback served, ddglitefail = lite tried and failed,
// ddgbackoff = search refused without contacting DDG.
$lite = 'https://lite.duckduckgo.com/lite/?q=' . urlencode($q);
$res = null; $results = []; $kind = 'blocked'; $viaLite = false; $refused = ''; $liteTried = false;
$viaBrave = false;
$primary = df_search_primary();
$ddgOn = df_ddg_enabled();
// Brave first when it is the primary backend (lib.php: df_search_primary). DDG
// below is then only the fallback, for when Brave fails or its cap is spent.
if ($primary === 'brave') {
    $b = df_brave_attempt($q, $s);
    if ($b === 'hourly' && !$ddgOn) df_search_busy_block();      // nothing else to try
    if (is_array($b)) { $results = $b; $kind = 'ok'; $viaBrave = true; }
}
$hcached = $ddgOn && $kind !== 'ok' && df_cache_get('raw:' . $ddg, 600) !== null;
if ($ddgOn && $kind !== 'ok' && ($hcached || df_ddg_backoff_remaining('html') === 0)) {
    if (!$hcached && ($refused = df_search_reserve()) !== '') {
        $refused === 'hourly' ? df_search_busy_block() : df_search_daily_block();
    }
    $res = http_get_cached($ddg, 600);           // 10-min search cache
    if ($res === null) {                         // network failure, not a DDG answer
        echo page_head('Results: ' . $q, true)
           . '<p><b>Search is temporarily unavailable.</b> Please try again in a moment.</p>'
           . page_foot();
        exit;
    }
    $results = parse_ddg($res['body']);
    $kind = $results ? 'ok' : df_ddg_page_kind($res['body'], (int)($res['status'] ?? 200));
    if ($kind === 'ok') {
        df_ddg_backoff_clear('html');
    } else {
        // a challenge or an unreadable page must not sit in the 10-min cache
        // looking like a real answer, and must never read as "No results found"
        df_cache_del('raw:' . $ddg);
        df_daily_inc($kind === 'blocked' ? 'ddgblocked' : 'ddgmarkup');
        if ($kind === 'blocked') df_ddg_backoff_hit('html');
    }
}
if ($ddgOn && $kind !== 'ok' && $s === 0) {
    $lcached = df_cache_get('raw:' . $lite, 600) !== null;
    if ($lcached || df_ddg_backoff_remaining('lite') === 0) {
        if (!$lcached && ($refused = df_search_reserve()) !== '' && $res === null) {
            // nothing was fetched at all: say which cap it was
            $refused === 'hourly' ? df_search_busy_block() : df_search_daily_block();
        }
        if ($lcached || $refused === '') {
            $lres = http_get_cached($lite, 600);
            $liteTried = true;
            $lkind = 'blocked';
            if ($lres !== null) {
                $results = parse_ddg_lite($lres['body']);
                $lkind = $results ? 'ok' : df_ddg_lite_page_kind($lres['body'], (int)($lres['status'] ?? 200));
            }
            if ($lkind === 'ok') {
                $kind = 'ok';
                $viaLite = true;
                df_ddg_backoff_clear('lite');
                df_daily_inc('ddglite');
            } else {
                $results = [];
                df_cache_del('raw:' . $lite);
                df_daily_inc('ddglitefail');
                if ($lkind === 'blocked' && $lres !== null) {
                    df_ddg_backoff_hit('lite');
                    $kind = 'blocked';           // say "unavailable", not "markup changed"
                }
            }
        }
    }
}
// With DDG primary, Brave is the fallback when DDG gave no usable answer. Both
// ways it takes a unit of the shared hourly cap and of its own daily cap
// ('brave', which also counts Brave requests); results are never cached.
if ($primary === 'ddg' && $kind !== 'ok') {
    $b = df_brave_attempt($q, $s);
    if ($b === 'hourly' && $res === null && !$liteTried) df_search_busy_block();   // nothing fetched at all
    if (is_array($b)) { $results = $b; $kind = 'ok'; $viaBrave = true; }
}
if (!$viaBrave && $res === null && !$liteTried) {
    // no backend answered and no DDG request was made: html is backing off (or
    // DDG is switched off) and lite was not fetched either (backing off, or a
    // deeper page lite can't serve)
    df_daily_inc($ddgOn ? 'ddgbackoff' : 'searchnone');
    $waits = $ddgOn ? array_filter([df_ddg_backoff_remaining('html'), $s === 0 ? df_ddg_backoff_remaining('lite') : 0])
                    : array_filter([df_ddg_backoff_remaining('brave')]);
    df_search_unavailable_block($waits ? min($waits) : 60);
}

echo page_head('Results: ' . $q, true);
echo '<form action="/" method="get">' . df_brand_link() . '&nbsp;&nbsp;'
   . '<input type="text" name="q" size="30" value="' . e($q) . '">&nbsp;'
   . '<input type="submit" value="Quack!"></form><hr>';

if ($kind !== 'ok') {
    echo $kind === 'blocked'
        ? '<p><b>Search is temporarily unavailable.</b> ' . df_search_engine_name() . ' is not answering '
          . DUCKFIND_NAME . '&#39;s searches right now. Please try again in a few minutes.</p>'
        : '<p><b>Search is temporarily broken.</b> ' . ($primary === 'brave' ? 'Brave Search is not answering and ' : '')
          . 'DuckDuckGo&#39;s results page has changed '
          . 'and ' . DUCKFIND_NAME . ' can&#39;t read it yet. Please try again later.</p>';
} elseif (!$results) {
    echo '<p>No results found for <b>' . e($q) . '</b>'
       . ($s > 0 ? ' at this depth. <a href="/?q=' . urlencode($q) . '">Back to the first page.</a>' : '.')
       . '</p>';
} else {
    echo '<ol start="' . ($s + 1) . '">';
    foreach ($results as $r) {
        $reader = '/read.php?url=' . urlencode($r['url']) . df_readtok_qs($r['url']);   // signed (lib.php)
        echo '<li><a href="' . e($reader) . '"><b>' . e($r['title']) . '</b></a>'
           . ' <font size="1">[<a href="' . e($r['url']) . '">direct</a>]</font><br>';
        echo '<font size="1" color="' . df_url_color() . '">' . e(df_shorten($r['url'])) . '</font>';
        if ($r['snippet'] !== '') echo '<br>' . e($r['snippet']);
        echo '<br>&nbsp;</li>';   // breathing room between results
    }
    echo '</ol>';
    if ($viaBrave) echo '<p><font size="1">' . ($primary === 'brave' ? 'Results from Brave Search.'
                       : 'DuckDuckGo is not answering right now; these results are from Brave Search.') . '</font></p>';
    // pagination nav (none for a lite fallback page, see above)
    // "< previous" goes back to the offset the visitor actually came from. Pages
    // hold different result counts, so s - count(this page) was wrong whenever
    // the previous page was longer or shorter (2026-11-12). The "more" link
    // carries the offsets walked so far in h (comma-separated, newest last).
    $hist = search_hist(df_str($_GET['h'] ?? ''), $s);
    $hq = function (array $h): string { return $h ? '&amp;h=' . implode(',', $h) : ''; };
    $nav = [];
    if ($s > 0) {
        $back = $hist;
        $ps = $back ? array_pop($back) : max(0, $s - count($results));   // no history: best guess
        $nav[] = '<a href="/?q=' . urlencode($q) . ($ps > 0 ? '&amp;s=' . $ps : '') . $hq($back) . '">&lt; previous</a>';
    }
    if (count($results) >= 10 && !$viaLite && !($viaBrave && $s + count($results) >= 100)) {
        $fwd = array_merge($hist, [$s]);
        $nav[] = '<a href="/?q=' . urlencode($q) . '&amp;s=' . ($s + count($results)) . $hq($fwd) . '">more results &gt;</a>';
    }
    if ($nav) echo '<hr><p>' . implode(' &nbsp;&middot;&nbsp; ', $nav) . '</p>';
}
echo page_foot();

function parse_ddg(string $html): array {
    $out = [];
    $dom = new DOMDocument();
    libxml_use_internal_errors(true);
    $dom->loadHTML('<?xml encoding="UTF-8" ?>' . $html);
    libxml_clear_errors();
    $xp = new DOMXPath($dom);
    $anchors = $xp->query('//a[contains(concat(" ", normalize-space(@class), " "), " result__a ")]');
    foreach ($anchors as $a) {
        $url = ddg_real_url($a->getAttribute('href'));
        if ($url === '') continue;
        $host = strtolower(parse_url($url, PHP_URL_HOST) ?? '');
        if ($host === '' || strpos($host, 'duckduckgo.com') !== false) continue; // skip ads / redirectors
        $title = trim($a->textContent);
        $snippet = '';
        $block = $xp->query('ancestor::div[contains(@class,"result__body") or contains(@class,"result")][1]', $a);
        if ($block->length) {
            $sn = $xp->query('.//*[contains(@class,"result__snippet")]', $block->item(0));
            if ($sn->length) $snippet = trim($sn->item(0)->textContent);
        }
        $out[] = ['title' => $title !== '' ? $title : $url, 'url' => $url, 'snippet' => $snippet];
        if (count($out) >= 30) break;
    }
    return $out;
}
// ddg_real_url(), parse_ddg_lite() and the canaries live in lib.php (testable).

// The search pager's back-trail: offsets (ascending, each below $s) the visitor
// walked through to reach offset $s. Anything malformed is dropped; at most 20.
function search_hist(string $h, int $s): array {
    $out = [];
    foreach (explode(',', $h) as $v) {
        if ($v === '' || !ctype_digit($v)) continue;
        $n = (int)$v;
        if ($n < $s && (!$out || $n > end($out))) $out[] = $n;
    }
    return array_slice($out, -20);
}

// Landing page for a tool's bang typed with nothing after it ("!weather"),
// or null for a bang that has none.
function bang_landing(string $bang): ?string {
    $landing = ['w' => '/wiki.php', 'wiki' => '/wiki.php', 'wb' => '/read.php', 'r' => '/read.php',
                'read' => '/read.php', 'pdf' => '/pdf.php', 'dl' => '/dl.php', 'download' => '/dl.php',
                'get' => '/dl.php', 'watch' => '/watch.php', 'ytsearch' => '/ytsearch.php',
                'yt' => '/ytsearch.php', 'weather' => '/weather.php', 'wx' => '/weather.php',
                'map' => '/map.php', 'dir' => '/map.php', 'directions' => '/map.php',
                'calc' => '/calc.php', 'convert' => '/calc.php', 'conv' => '/calc.php',
                'translate' => '/translate.php', 'tr' => '/translate.php', 'ebook' => '/ebook.php',
                'book' => '/ebook.php', 'wiby' => '/wiby.php', 'gopher' => '/gopher.php',
                'ftp' => '/ftp.php', 'define' => '/define.php', 'def' => '/define.php',
                'd' => '/define.php', 'ai' => '/ask.php'];
    return $landing[$bang] ?? null;
}
