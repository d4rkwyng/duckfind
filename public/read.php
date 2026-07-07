<?php
require __DIR__ . '/lib.php';
if (!df_rate('read')) df_rate_block();
header('Content-Type: text/html; charset=iso-8859-1');

$url = df_input('url');
if ($url !== '' && !preg_match('#^[a-z]+://#i', $url)) $url = 'https://' . $url;

// image mode: on by default, ?img=0 for text-only (persisted through article links)
define('DF_IMAGES', (($_GET['img'] ?? '') !== '0'));
// colour rendering: color (default), gray, or bw (dithered) -- for low-colour displays
$im = strtolower($_GET['im'] ?? 'color');
define('DF_IMGMODE', in_array($im, ['gray', 'bw'], true) ? $im : 'color');
// output format: html (default) or plain text (?fmt=txt) for MacLynx / Apple II
$fmt = (($_GET['fmt'] ?? '') === 'txt') ? 'txt' : 'html';
// Wayback Machine: ?year=YYYY (or full 14-digit timestamp) reads an archived copy
define('DF_YEAR', preg_replace('/\D/', '', (string)($_GET['year'] ?? '')));

if (!preg_match('#^https?://#i', $url)) {
    echo page_head('Read a page', true) . '<p>Provide a URL to read, e.g. '
       . '<tt>/read.php?url=https://example.com</tt></p>' . page_foot();
    exit;
}

// Wayback: rewrite the fetch through web.archive.org when a year is given.
// The "id_" suffix returns the original archived bytes without the WB toolbar.
$fetchUrl = $url;
if (DF_YEAR !== '') {
    $ts = DF_YEAR;
    if (strlen($ts) === 4) $ts .= '0601';                 // bare year -> mid-year
    $ts = substr(str_pad($ts, 14, '0'), 0, 14);
    $fetchUrl = 'https://web.archive.org/web/' . $ts . 'id_/' . $url;
}

$res = http_get_cached($fetchUrl, DF_YEAR !== '' ? 86400 : 1800);
if ($res === null || ($res['ctype'] !== '' && !preg_match('#text/html|application/xhtml#i', $res['ctype']))) {
    // offer a Wayback snapshot if the live page is gone
    $extra = '';
    if (DF_YEAR === '') {
        $av = http_get('https://archive.org/wayback/available?url=' . urlencode($url), 200000);
        if ($av && ($j = json_decode($av['body'], true))
            && !empty($j['archived_snapshots']['closest']['timestamp'])) {
            $ty = substr($j['archived_snapshots']['closest']['timestamp'], 0, 4);
            $uu = htmlspecialchars(urlencode($url), ENT_QUOTES);
            $extra = '<p><b>The live page didn\'t load</b> &mdash; but the Wayback Machine has a copy from '
                   . e($ty) . '. [<a href="/read.php?url=' . $uu . '&amp;year=' . e($ty) . '">read the '
                   . e($ty) . ' version</a>]</p>';
        }
    }
    echo page_head('Read a page', true)
       . '<p><b>Could not load</b> <tt>' . e($url) . '</tt></p>' . $extra
       . '<p>[<a href="' . e($url) . '">try it directly</a>]</p>' . page_foot();
    exit;
}

[$title, $content, $next] = extract_readable($res['body'], $url, $res['ctype']);

// Anti-bot / JS-challenge interstitial? Show a useful message rather than
// rendering "Just a moment..." as if it were the article.
$plain = trim(preg_replace('/\s+/', ' ', strip_tags($content)));
if (strlen($plain) < 600 && preg_match('/just a moment|checking your browser|enable javascript|'
    . 'attention required|verify (you are|that you are) human|cf-browser-verification|'
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
$yp = DF_YEAR !== '' ? '&amp;year=' . DF_YEAR : '';   // thread Wayback era through links
$modes = '';
if (DF_IMAGES) {
    $links = [];
    foreach (['color' => 'color', 'gray' => 'gray', 'bw' => 'b&amp;w'] as $k => $label) {
        $href = '/read.php?url=' . $uq . ($k !== 'color' ? '&amp;im=' . $k : '') . $yp;
        $links[] = ($k === DF_IMGMODE) ? "<b>$label</b>" : '<a href="' . $href . '">' . $label . '</a>';
    }
    $modes = ' &middot; img: ' . implode(' ', $links);
}
$toggle = DF_IMAGES
    ? '<a href="/read.php?url=' . $uq . '&amp;img=0' . $yp . '">[text only]</a>' . $modes
    : '<a href="/read.php?url=' . $uq . $yp . '">[show images]</a>';
$toggle .= ' &middot; <a href="/read.php?url=' . $uq . '&amp;fmt=txt' . $yp . '">[plain text]</a>';

echo page_head($title !== '' ? $title : $url, true);
echo '<form action="/" method="get"><a href="/"><b>' . DUCKFIND_NAME . '</b></a>&nbsp;&nbsp;'
   . '<input type="text" name="q" size="24">&nbsp;<input type="submit" value="Search">'
   . '&nbsp;&nbsp;<font size="1">' . $toggle . '</font></form>';
echo '<font size="1">Reading: <a href="' . e($url) . '">' . e($url) . '</a></font><br>';
// Wayback era switcher — flip the current page to an archived year in one click
$wb = '<font size="1">Wayback:';
foreach (['1998' => "'98", '2002' => "'02", '2006' => "'06", '2010' => "'10",
          '2015' => "'15", '2020' => "'20"] as $yr => $lbl) {
    $on = (DF_YEAR !== '' && substr(DF_YEAR, 0, 4) === $yr);
    $wb .= ' ' . ($on ? "<b>[$lbl]</b>"
                      : '<a href="/read.php?url=' . $uq . '&amp;year=' . $yr . '">' . $lbl . '</a>');
}
$wb .= DF_YEAR !== '' ? ' &middot; <a href="/read.php?url=' . $uq . '"><b>live</b></a>' : ' &middot; <i>live</i>';
echo $wb . '</font><hr>';
if ($title !== '') echo '<h1>' . e($title) . '</h1>';
echo $content;

// #10 multi-page stitching: offer the article's own "next page" link
if ($next !== '') {
    $nabs = absolutize($url, $next);
    if (preg_match('#^https?://#i', $nabs)) {
        $np = (DF_IMAGES ? '' : '&amp;img=0') . (DF_IMGMODE !== 'color' ? '&amp;im=' . DF_IMGMODE : '') . $yp;
        echo '<hr><p align="center"><a href="/read.php?url=' . htmlspecialchars(urlencode($nabs), ENT_QUOTES)
           . $np . '"><b>Next page &gt;</b></a></p>';
    }
}
echo page_foot();

// ---------------------------------------------------------------------------

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
    $ps = $scope ? $xp->query($q, $scope) : $xp->query(substr(str_replace('.//', '//', $q), 0));
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
        $imgParam = DF_IMAGES ? '' : '&amp;img=0';
        if (DF_IMGMODE !== 'color') $imgParam .= '&amp;im=' . DF_IMGMODE;   // persist colour mode
        if (DF_YEAR !== '')         $imgParam .= '&amp;year=' . DF_YEAR;    // stay in the same era
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
