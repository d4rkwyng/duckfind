<?php
require __DIR__ . '/lib.php';
if (!df_rate('read')) df_rate_block();
header('Content-Type: text/html; charset=iso-8859-1');

$url = df_input('url');
if ($url !== '' && !preg_match('#^[a-z]+://#i', $url)) $url = 'https://' . $url;

// display prefs: an explicit query param wins, else the saved cookie, else default
$prefImg = ($_COOKIE['df_img'] ?? '1') !== '0';
define('DF_IMAGES', isset($_GET['img']) ? ($_GET['img'] !== '0') : $prefImg);
// colour rendering: color (default), gray, or bw (dithered) -- for low-colour displays
$prefMode = $_COOKIE['df_mode'] ?? 'color';
$im = strtolower($_GET['im'] ?? $prefMode);
define('DF_IMGMODE', in_array($im, ['gray', 'bw'], true) ? $im : 'color');
// output format: html (default) or plain text (?fmt=txt) for MacLynx / Apple II
$fmt = (($_GET['fmt'] ?? '') === 'txt') ? 'txt' : 'html';
// Wayback Machine: ?year=YYYY (or full 14-digit timestamp) reads an archived copy
define('DF_YEAR', preg_replace('/\D/', '', (string)($_GET['year'] ?? '')));
// Render mode: reader (extract the article) vs original layout (pass through,
// preserving tables/fonts/image-nav). Original is the default for Wayback, since
// era-appropriate pages were built for old browsers; reader for live pages.
$rawParam = $_GET['raw'] ?? '';
define('DF_RAW', $rawParam === '1' || ($rawParam === '' && DF_YEAR !== ''));

if (!preg_match('#^https?://#i', $url)) {
    echo page_head(DUCKFIND_NAME . ' - reader', true);
    echo '<form action="/read.php" method="get"><a href="/"><b>' . DUCKFIND_NAME . '</b></a>&nbsp;&nbsp;'
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

// Wayback: rewrite the fetch through web.archive.org when a year is given.
// The "id_" suffix returns the original archived bytes without the WB toolbar.
if (DF_YEAR !== '') {
    $ts = DF_YEAR;
    if (strlen($ts) === 4) $ts .= '0601';                 // bare year -> mid-year
    $ts = substr(str_pad($ts, 14, '0'), 0, 14);
    $res = df_wayback_get($ts, $url, 86400);
} else {
    $res = http_get_cached($url, 1800);
}
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
        $av = http_get('https://archive.org/wayback/available?url=' . urlencode($url), 200000);
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
$next = '';
$recipe = (!DF_RAW && $fmt !== 'txt') ? extract_recipe($res['body'], $url) : null;
if ($recipe !== null) {
    [$title, $content] = $recipe;
} elseif (DF_RAW && $fmt !== 'txt') {
    [$title, $content] = render_original($res['body'], $url, $res['ctype']);
} else {
    [$title, $content, $next] = extract_readable($res['body'], $url, $res['ctype']);
}

// Anti-bot / JS-challenge interstitial? Show a useful message rather than
// rendering "Just a moment..." as if it were the article. (Reader-mode only —
// a full challenge page in original mode would be large and not match.)
$plain = trim(preg_replace('/\s+/', ' ', strip_tags($content)));
if (strlen($plain) < 600 && preg_match('/just a moment|checking your browser|'
    . 'enable javascript|enable js|ad ?blocker|attention required|'
    . 'verify (you are|that you are) human|cf-browser-verification|'
    . 'access denied|unusual traffic|are you a robot|please enable cookies/i', $title . ' ' . $plain)) {
    $uu = htmlspecialchars(urlencode($url), ENT_QUOTES);
    $wbl = '';
    if (DF_YEAR === '') {
        $av = http_get('https://archive.org/wayback/available?url=' . urlencode($url), 200000);
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
    $t = preg_replace('#<li\b[^>]*>#i', "\n * ", $content);
    $t = preg_replace('#</(p|h[1-6]|tr|div|blockquote)>#i', "\n\n", $t);
    $t = preg_replace('#<(br|hr)\b[^>]*>#i', "\n", $t);
    $t = html_entity_decode(strip_tags($t), ENT_QUOTES, 'UTF-8');
    $t = preg_replace('/[ \t]+/', ' ', $t);
    $t = preg_replace('/\n{3,}/', "\n\n", $t);
    if ($title !== '') echo df_translit($title) . "\n" . str_repeat('=', min(70, strlen($title))) . "\n\n";
    echo trim(df_translit($t)) . "\n\n----\nsource: " . $url . "\n";
    exit;
}

$uq = htmlspecialchars(urlencode($url), ENT_QUOTES);
$yp = DF_YEAR !== '' ? '&amp;year=' . DF_YEAR : '';        // thread Wayback era through links
$rp = '&amp;raw=' . (DF_RAW ? '1' : '0');                  // thread render mode through links
$modes = '';
if (DF_IMAGES) {
    $links = [];
    foreach (['color' => 'color', 'gray' => 'gray', 'bw' => 'b&amp;w'] as $k => $label) {
        $href = '/read.php?url=' . $uq . ($k !== 'color' ? '&amp;im=' . $k : '') . $yp . $rp;
        $links[] = ($k === DF_IMGMODE) ? "<b>$label</b>" : '<a href="' . $href . '">' . $label . '</a>';
    }
    $modes = ' &middot; img: ' . implode(' ', $links);
}
$toggle = DF_IMAGES
    ? '<a href="/read.php?url=' . $uq . '&amp;img=0' . $yp . $rp . '">[text only]</a>' . $modes
    : '<a href="/read.php?url=' . $uq . $yp . $rp . '">[show images]</a>';
$toggle .= ' &middot; <a href="/read.php?url=' . $uq . '&amp;fmt=txt' . $yp . '">[plain text]</a>';
// view picker, same idiom as the img modes: bold = active, link = available
$toggle .= ' &middot; view: '
    . (DF_RAW ? '<a href="/read.php?url=' . $uq . '&amp;raw=0' . $yp . '">reader</a>' : '<b>reader</b>')
    . ' '
    . (DF_RAW ? '<b>original</b>' : '<a href="/read.php?url=' . $uq . '&amp;raw=1' . $yp . '">original</a>');

echo page_head($title !== '' ? $title : $url, true);
echo '<form action="/" method="get"><a href="/"><b>' . DUCKFIND_NAME . '</b></a>&nbsp;&nbsp;'
   . '<input type="text" name="q" size="24">&nbsp;<input type="submit" value="Quack!">'
   . '&nbsp;&nbsp;<font size="1">' . $toggle . '</font></form>';
echo '<font size="1">Reading: <a href="' . e($url) . '">' . e($url) . '</a></font><br>';
// Wayback era switcher — flip the current page to an archived year in one click
$wb = '<font size="1">Wayback:';
foreach (['1998' => "'98", '2002' => "'02", '2006' => "'06", '2010' => "'10",
          '2015' => "'15", '2020' => "'20"] as $yr => $lbl) {
    $on = (DF_YEAR !== '' && substr(DF_YEAR, 0, 4) === $yr);
    $wb .= ' ' . ($on ? "<b>[$lbl]</b>"
                      : '<a href="/read.php?url=' . $uq . '&amp;year=' . $yr . $rp . '">' . $lbl . '</a>');
}
$wb .= DF_YEAR !== '' ? ' &middot; <a href="/read.php?url=' . $uq . '"><b>live</b></a>' : ' &middot; <i>live</i>';
echo $wb . '</font><hr>';
if ($title !== '') echo '<h1>' . e($title) . '</h1>';
echo $content;

// #10 multi-page stitching: offer the article's own "next page" link
if ($next !== '') {
    $nabs = absolutize($url, $next);
    if (preg_match('#^https?://#i', $nabs)) {
        $np = (DF_IMAGES ? '' : '&amp;img=0') . (DF_IMGMODE !== 'color' ? '&amp;im=' . DF_IMGMODE : '') . $yp . $rp;
        echo '<hr><p align="center"><a href="/read.php?url=' . htmlspecialchars(urlencode($nabs), ENT_QUOTES)
           . $np . '"><b>Next page &gt;</b></a></p>';
    }
}
echo page_foot();

// ---------------------------------------------------------------------------

// If the page carries a schema.org/Recipe in JSON-LD, render a clean card
// (ingredients + numbered steps) and return [title, html]; else null. Fast
// string bail keeps this near-free on the vast majority of pages. Handles the
// usual schema variance: @graph wrappers, @type as string or array, image as
// string/array/ImageObject, instructions as string / string[] / HowToStep[] /
// HowToSection[].
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
        $iq = '&amp;w=480' . (DF_IMGMODE !== 'color' ? '&amp;im=' . DF_IMGMODE : '');
        $out .= '<p><img src="/img.php?url=' . htmlspecialchars(urlencode($abs), ENT_QUOTES) . $iq
              . '" alt="" border="0"></p>';
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
    $out .= '<hr><p><font size="1">Recipe view &mdash; [<a href="/read.php?url='
          . htmlspecialchars(urlencode($baseUrl), ENT_QUOTES) . '&amp;raw=1">full page</a>]</font></p>';
    return [$name !== '' ? $name : 'Recipe', $out];
}

// Flatten a JSON-LD blob into a list of candidate objects (handles @graph and
// arrays of objects at the top level).
function rc_flatten($j): array {
    $out = [];
    if (isset($j['@graph']) && is_array($j['@graph'])) { foreach ($j['@graph'] as $g) $out[] = $g; }
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
    $xp = new DOMXPath($dom);

    // title preference: og:title (post-level, most reliable) > first h1 > <title>
    $title = '';
    if (($t = $xp->query('//title'))->length) $title = trim($t->item(0)->textContent);
    if (($h = $xp->query('//h1'))->length) { $h1 = trim($h->item(0)->textContent); if ($h1 !== '') $title = $h1; }
    $og = $xp->query('//meta[@property="og:title" or @name="og:title"]/@content');
    if ($og->length && trim($og->item(0)->nodeValue) !== '') $title = trim($og->item(0)->nodeValue);

    // honour <base href> so relative links/images resolve correctly
    $b = $xp->query('//base[@href]/@href');
    if ($b->length && trim($b->item(0)->nodeValue) !== '') {
        $baseUrl = absolutize($baseUrl, trim($b->item(0)->nodeValue));
    }

    // detect a "next page" link before we strip <link>/<a rel> chrome
    $next = '';
    $nl = $xp->query('//link[@rel="next"]/@href | //a[@rel="next"]/@href');
    if ($nl->length) $next = trim($nl->item(0)->nodeValue);

    // 1. strip junk tags outright (h1 too: we emit the title as the one heading)
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
    foreach ($doomed as $el) if ($el->parentNode) $el->parentNode->removeChild($el);

    // 3. scope to semantic containers when present and substantial
    $scope = null;
    foreach (['//main', '//*[@role="main"]', '//article'] as $q) {
        $n = $xp->query($q);
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
            $txt = max(1, strlen(trim($c['el']->textContent)));
            $ltxt = 0;
            foreach ($xp->query('.//a', $c['el']) as $a) $ltxt += strlen(trim($a->textContent));
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

    $out = render_node($best, $baseUrl);
    if (trim(strip_tags($out)) === '') {
        $body = $xp->query('//body');
        $out = $body->length ? render_node($body->item(0), $baseUrl) : '<p>(no readable text found)</p>';
    }
    // tidy: collapse <br> runs, drop empty paragraphs, pad empty table cells
    // (empty <td> renders borderless on Netscape-era engines -- classic fix is &nbsp;)
    $out = preg_replace('#(<br>\s*){3,}#i', '<br><br>', $out);
    // adjacent inline links (nav/button rows) have no whitespace between them in
    // source -> "LinkALinkB"; separate them and any link glued to a following word
    $out = preg_replace('#</a>\s*<a\b#i', '</a> <a', $out);
    $out = preg_replace('#</a>(?=[A-Z0-9])#', '</a> ', $out);
    $out = preg_replace('#<p>\s*</p>#i', '', $out);
    $out = preg_replace('#<caption>\s*</caption>#i', '', $out);
    $out = preg_replace('#<(td|th)([^>]*)>\s*</\1>#i', '<$1$2>&nbsp;</$1>', $out);
    return [$title, ascii_html($out), $next];
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
            return '<a href="/dl.php?url=' . htmlspecialchars(urlencode($abs), ENT_QUOTES) . '">' . $inner . '</a>';
        }
        $q = (DF_IMAGES ? '' : '&amp;img=0') . (DF_IMGMODE !== 'color' ? '&amp;im=' . DF_IMGMODE : '')
           . (DF_YEAR !== '' ? '&amp;year=' . DF_YEAR : '') . '&amp;raw=1';
        return '<a href="/read.php?url=' . htmlspecialchars(urlencode($abs), ENT_QUOTES) . $q . '">' . $inner . '</a>';
    }

    if (!in_array($tag, $keep, true)) return $inner . ' ';         // drop tag, keep contents
    if (in_array($tag, $void, true)) return "<$tag>";
    return '<' . $tag . safe_attrs($node) . '>' . $inner . '</' . $tag . '>';
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
        $cap = strlen($alt) > 3
             ? '<br><font size="1"><i>' . htmlspecialchars($alt, ENT_QUOTES) . '</i></font>' : '';
        $mode = DF_IMGMODE !== 'color' ? '&amp;im=' . DF_IMGMODE : '';
        if (DF_YEAR !== '') $mode .= '&amp;year=' . DF_YEAR;   // pull era-correct image from Wayback
        return '<br><img src="/img.php?url=' . htmlspecialchars(urlencode($abs), ENT_QUOTES) . $mode
             . '" alt="' . htmlspecialchars($alt, ENT_QUOTES) . '" border="0">' . $cap . '<br>';
    }

    $inner = '';
    foreach ($node->childNodes as $c) $inner .= render_node($c, $baseUrl);

    if ($tag === 'a') {
        $href = $node->getAttribute('href');
        if ($href === '' || trim($inner) === '') return $inner;
        $abs = absolutize($baseUrl, $href);
        if (!preg_match('#^https?://#i', $abs)) return $inner;
        if (df_is_download($abs)) {   // binary/archive -> download proxy, not the reader
            return '<a href="/dl.php?url=' . htmlspecialchars(urlencode($abs), ENT_QUOTES) . '">' . $inner . '</a>';
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
        return '<a href="/read.php?url=' . htmlspecialchars(urlencode($abs), ENT_QUOTES) . $imgParam . '">' . $inner . '</a>';
    }
    if (!in_array($tag, $allowed, true)) {
        // Drop the tag, keep its text. Add a separating space UNLESS the tag is a
        // known inline element -- so block wrappers AND custom web-component tags
        // (<blz-button>, <my-card>, anything hyphenated) don't glue adjacent text
        // together, while real inline markup (<span>, <font>) keeps words intact.
        static $inline = ['span','font','small','label','abbr','cite','q','mark','u','s',
                          'strike','tt','big','wbr','bdi','bdo','ins','del','time','data',
                          'output','kbd','samp','var','ruby','rt','rp','nobr','acronym'];
        return in_array($tag, $inline, true) ? $inner : $inner . ' ';
    }
    if ($tag === 'br' || $tag === 'hr') return "<$tag>";
    if ($tag === 'table') return '<table border="1" cellpadding="3" cellspacing="0">' . $inner . '</table>';
    if ($tag === 'td' || $tag === 'th') {                        // keep spans or the grid shears
        $attrs = '';
        foreach (['colspan', 'rowspan'] as $at) {
            $v = (int)$node->getAttribute($at);
            if ($v > 1) $attrs .= ' ' . $at . '="' . $v . '"';
        }
        return "<$tag$attrs>" . $inner . "</$tag>";
    }
    return "<$tag>" . $inner . "</$tag>";
}
