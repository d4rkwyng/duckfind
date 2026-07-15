<?php
require __DIR__ . '/lib.php';
header('Content-Type: text/html; charset=iso-8859-1');

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
        // let Wikipedia resolve the real title (casing, apostrophes, redirects)
        $wiki = 'https://en.wikipedia.org/w/index.php?title=Special:Search&go=Go&search=' . rawurlencode($rest);
        $go = '/read.php?url=' . urlencode($wiki);
    } elseif ($bang === 'wb' && $rest !== '') {
        $a = preg_split('/\s+/', $rest);
        $yr = (isset($a[count($a) - 1]) && preg_match('/^\d{4}$/', $a[count($a) - 1])) ? array_pop($a) : '';
        $tgt = implode(' ', $a);
        if (!preg_match('#^https?://#i', $tgt)) $tgt = 'https://' . $tgt;
        $go = '/read.php?url=' . urlencode($tgt) . ($yr !== '' ? '&year=' . $yr : '');
    } elseif (($bang === 'r' || $bang === 'read') && $rest !== '') {
        if (!preg_match('#^https?://#i', $rest)) $rest = 'https://' . $rest;
        $go = '/read.php?url=' . urlencode($rest);
    } elseif ($bang === 'news') {
        $go = '/news.php';
    } elseif ($bang === 'feeds') {
        $go = '/feeds.php';
    } elseif (($bang === 'weather' || $bang === 'wx') && $rest !== '') {
        $go = '/weather.php?q=' . urlencode($rest);
    } elseif ($bang === 'map' && $rest !== '') {
        $go = '/map.php?q=' . urlencode($rest);
    } elseif (($bang === 'calc' || $bang === 'convert' || $bang === 'conv') && $rest !== '') {
        $go = '/calc.php?q=' . urlencode($rest);
    } elseif (($bang === 'translate' || $bang === 'tr') && $rest !== '') {
        $go = '/translate.php?q=' . urlencode($rest);
    } elseif ($bang === 'wiby' && $rest !== '') {
        $go = '/wiby.php?q=' . urlencode($rest);
    } elseif ($bang === 'surprise') {
        $go = '/wiby.php?surprise=1';
    } elseif ($bang === 'gopher' && $rest !== '') {
        if (!preg_match('#^gopher://#i', $rest)) $rest = 'gopher://' . $rest;
        $go = '/gopher.php?url=' . urlencode($rest);
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
    if ($go !== null) { header('Location: ' . $go, true, 302); exit; }   // 302 = widest old-browser support
    // unknown bang -> drop the "!tag" and just search the remaining words
    $q = $rest;
}

if ($q === '') {
    echo page_head(DUCKFIND_NAME . ' - retro web search & reader');
    echo '<center>' . "\n";
    echo '<table width="460" border="0" cellpadding="0" cellspacing="0"><tr><td align="center">' . "\n";

    // masthead
    echo '<br><img src="/duck.gif?v=4" alt="[DuckFind]" width="128" height="120" border="0"><br>' . "\n";
    echo '<font size="6"><b>' . DUCKFIND_NAME . '</b></font><br>' . "\n";
    echo '<font size="2"><i>the vintage web, in plain HTML</i></font>' . "\n";

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
           . '<font size="1">[<a href="/">hide</a>]</font> &mdash; type in the box above:<br>' . "\n";
        if (df_cfg('ai_api_key', '') !== '')
            echo '<tt>!ai</tt> <i>question</i> &mdash; get an AI answer<br>' . "\n";
        echo '<tt>!w</tt> <i>term</i> &mdash; jump to a Wikipedia article<br>' . "\n";
        echo '<tt>!wb</tt> <i>url</i> [<i>year</i>] &mdash; read a Wayback Machine copy<br>' . "\n";
        echo '<tt>!r</tt> <i>url</i> &mdash; read any page directly<br>' . "\n";
        echo '<tt>!weather</tt> <i>place</i> &mdash; 5-day forecast<br>' . "\n";
        echo '<tt>!map</tt> <i>place</i> &mdash; street map, pan &amp; zoom<br>' . "\n";
        echo '<tt>!dir</tt> <i>a</i> to <i>b</i> &mdash; driving directions<br>' . "\n";
        echo '<tt>!gopher</tt> <i>host</i> &mdash; browse gopherspace<br>' . "\n";
        echo '<tt>!wiby</tt> <i>term</i> &mdash; search the classic web (Wiby)<br>' . "\n";
        echo '<tt>!surprise</tt> &mdash; a random classic page<br>' . "\n";
        echo '<tt>!translate</tt> <i>text</i> to <i>language</i> &mdash; translator<br>' . "\n";
        echo '<tt>!calc</tt> <i>2+2*7</i> &mdash; calculator<br>' . "\n";
        echo '<tt>!convert</tt> <i>5 mi to km</i> &mdash; units &amp; currency<br>' . "\n";
        echo '<tt>!define</tt> <i>word</i> &mdash; dictionary lookup<br>' . "\n";
        echo '<tt>!news</tt> &mdash; jump to the news portal<br>' . "\n";
        echo '<tt>!feeds</tt> &mdash; your personal feed reader</font>' . "\n";
        echo '</td></tr></table>' . "\n";
    }

    echo '</td></tr></table>' . "\n";
    echo '</center>' . "\n";
    echo page_foot();
    exit;
}

if (!df_rate('search')) df_rate_block();
$s   = max(0, (int)($_GET['s'] ?? 0));           // result offset for pagination
$ddg = 'https://html.duckduckgo.com/html/?q=' . urlencode($q) . ($s > 0 ? '&s=' . $s : '');

// Site-wide daily ceiling on outbound DuckDuckGo fetches. Per-IP limits don't
// stop a botnet (every bot gets a fresh bucket), and enough scraped searches
// would get our server IP blocked by DDG — killing search for everyone. Only
// cache misses count, so already-seen searches keep working at the cap.
if (df_cache_get('raw:' . $ddg, 600) === null) {
    $cap = (int)df_cfg('search_daily_cap', 5000);
    if ($cap > 0 && df_daily_count('search') >= $cap) {
        http_response_code(429);
        header('Content-Type: text/html; charset=iso-8859-1');
        echo page_head('Search limit reached', true)
           . '<h1>Daily search limit reached</h1>'
           . '<p>DuckFind has run as many new searches as it can for today '
           . '(a site-wide cap protects the search backend for everyone; see the '
           . '<a href="/about.php">about page</a>). '
           . 'Recently searched terms still work. Please try again tomorrow.</p>'
           . page_foot();
        exit;
    }
    df_daily_inc('search');
}
$res = http_get_cached($ddg, 600);               // 10-min search cache

echo page_head('Results: ' . $q, true);
echo '<form action="/" method="get"><a href="/"><b>' . DUCKFIND_NAME . '</b></a>&nbsp;&nbsp;'
   . '<input type="text" name="q" size="30" value="' . e($q) . '">&nbsp;'
   . '<input type="submit" value="Quack!"></form><hr>';

if ($res === null) {
    echo '<p><b>Search is temporarily unavailable.</b> Please try again in a moment.</p>';
    echo page_foot();
    exit;
}

$results = parse_ddg($res['body']);
if (!$results) {
    echo '<p>No results found for <b>' . e($q) . '</b>'
       . ($s > 0 ? ' at this depth. <a href="/?q=' . urlencode($q) . '">Back to the first page.</a>' : '.')
       . '</p>';
} else {
    echo '<ol start="' . ($s + 1) . '">';
    foreach ($results as $r) {
        $reader = '/read.php?url=' . urlencode($r['url']);
        echo '<li><a href="' . e($reader) . '"><b>' . e($r['title']) . '</b></a>'
           . ' <font size="1">[<a href="' . e($r['url']) . '">direct</a>]</font><br>';
        echo '<font size="1" color="' . df_url_color() . '">' . e($r['url']) . '</font>';
        if ($r['snippet'] !== '') echo '<br>' . e($r['snippet']);
        echo '<br>&nbsp;</li>';   // breathing room between results
    }
    echo '</ol>';
    // pagination nav
    $nav = [];
    if ($s > 0) {
        $ps = max(0, $s - count($results));
        $nav[] = '<a href="/?q=' . urlencode($q) . ($ps > 0 ? '&amp;s=' . $ps : '') . '">&lt; previous</a>';
    }
    if (count($results) >= 10) {
        $nav[] = '<a href="/?q=' . urlencode($q) . '&amp;s=' . ($s + count($results)) . '">more results &gt;</a>';
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

function ddg_real_url(string $href): string {
    if ($href === '') return '';
    if (strpos($href, 'uddg=') !== false) {
        parse_str(parse_url($href, PHP_URL_QUERY) ?? '', $qs);
        if (!empty($qs['uddg'])) return $qs['uddg'];
    }
    if (strpos($href, '//') === 0) return 'https:' . $href;
    if (preg_match('#^https?://#', $href)) return $href;
    return '';
}
