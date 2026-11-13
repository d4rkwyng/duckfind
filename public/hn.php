<?php
// DuckFind × Hacker News — read HN and its comment threads on a vintage browser.
// The linked article already opens fine in read.php; the DISCUSSION is what a
// JS-free browser can't reach (HN renders comments client-side). This uses HN's
// keyless Firebase JSON API to render the front page as a headline list and any
// story as its full comment thread in nested plain HTML. Reuses the SSRF-safe
// fetcher + disk cache; comment HTML is sanitised to a tiny tag allowlist and
// every link is routed through the reader so it opens on an old browser too.
require __DIR__ . '/lib.php';
if (!df_rate('news')) df_rate_block();
header('Content-Type: text/html; charset=iso-8859-1');

define('HN_API', 'https://hacker-news.firebaseio.com/v0');
define('HN_FRONT', 30);          // stories on the front page
define('HN_MAX_COMMENTS', 200);  // comments fetched per thread
define('HN_INDENT_CAP', 4);      // stop indenting past this depth (narrow screens)
define('HN_PARALLEL', 16);       // comment items fetched at once per batch
define('HN_BUDGET', 8.0);        // seconds spent fetching a thread's comments
define('HN_FRONT_BUDGET', 8.0);  // seconds spent fetching front-page story items

$lists = ['top' => 'topstories', 'new' => 'newstories', 'best' => 'beststories',
          'ask' => 'askstories', 'show' => 'showstories'];
$id   = (int)($_GET['id'] ?? 0);
// is_string guard: ?list[]=x would otherwise TypeError the isset() into a 500
$list = (isset($_GET['list']) && is_string($_GET['list']) && isset($lists[$_GET['list']])) ? $_GET['list'] : 'top';

echo page_head(DUCKFIND_NAME . ' - Hacker News' . ($id > 0 ? '' : ' (' . $list . ')'));
echo '<form action="/" method="get">' . df_brand_link() . '&nbsp;&nbsp;'
   . '<input type="text" name="q" size="26">&nbsp;<input type="submit" value="Quack!"></form>';

if ($id > 0) {
    hn_thread($id);
} else {
    // list switcher
    $nav = [];
    foreach ($lists as $k => $_) {
        $nav[] = $k === $list ? '<b>' . $k . '</b>' : '<a href="/hn.php?list=' . $k . '">' . $k . '</a>';
    }
    echo '<font size="1">Hacker News: ' . implode(' &middot; ', $nav) . '</font><hr>';
    hn_front($lists[$list]);
}
echo page_foot();

// ---------------------------------------------------------------------------
// Front page: a numbered list of stories. Each title opens the article in the
// reader (or the thread, for text posts); the comment count opens the thread.
// ---------------------------------------------------------------------------
function hn_front(string $endpoint): void {
    $r = http_get_cached(HN_API . '/' . $endpoint . '.json', 300);
    $ids = $r ? json_decode($r['body'], true) : null;
    if (!is_array($ids)) { echo '<p><b>Hacker News is not answering right now.</b></p>'; return; }
    $ids = array_slice($ids, 0, HN_FRONT);
    // hn_thread() already guards its own comment-fetch loop with HN_BUDGET;
    // this loop (up to 30 sequential story fetches) had no equivalent -- a
    // cold cache plus HN's API merely slowing down (not hard-failing) could
    // hold a worker far longer than any single request should. Same
    // truncate-and-note pattern as hn_thread() rather than hanging.
    $deadline = microtime(true) + HN_FRONT_BUDGET;
    $truncated = false;
    echo '<ol>';
    foreach ($ids as $sid) {
        if (microtime(true) >= $deadline) { $truncated = true; break; }
        $it = hn_item((int)$sid);
        if (!$it || empty($it['title'])) continue;
        $thread = '/hn.php?id=' . (int)$sid;
        $target = !empty($it['url']) ? '/read.php?url=' . htmlspecialchars(urlencode($it['url']), ENT_QUOTES)
                                       . df_readtok_qs((string)$it['url'], true)   // signed (lib.php)
                                     : $thread;
        $host = !empty($it['url']) ? ' <font size="1" color="' . df_muted_color() . '">('
              . e(preg_replace('#^www\.#', '', (string)parse_url($it['url'], PHP_URL_HOST))) . ')</font>' : '';
        echo '<li><a href="' . $target . '"><b>' . e((string)$it['title']) . '</b></a>' . $host . '<br>'
           . '<font size="1" color="' . df_muted_color() . '">' . (int)($it['score'] ?? 0) . ' points by '
           . e((string)($it['by'] ?? '?')) . ' &middot; '
           . '<a href="' . $thread . '">' . (int)($it['descendants'] ?? 0) . ' comments</a></font>'
           . '<br>&nbsp;</li>';
    }
    echo '</ol>';
    if ($truncated) {
        echo '<p><font size="1">(the rest of this list was not loaded to keep the page quick -- '
           . 'reload to try again)</font></p>';
    }
}

// ---------------------------------------------------------------------------
// Thread: story header + the whole comment tree, breadth-first within a time
// and comment budget so a huge thread can't hang a worker, then rendered nested.
// ---------------------------------------------------------------------------
function hn_thread(int $id): void {
    $story = hn_item($id);
    if (!$story) { echo '<p><b>Could not load that thread.</b> [<a href="/hn.php">front page</a>]</p>'; return; }
    echo '<font size="1"><a href="/hn.php">&lt; Hacker News front page</a></font><hr>';
    $title = (string)($story['title'] ?? '(comment)');
    if (!empty($story['url'])) {
        echo '<h2><a href="/read.php?url=' . htmlspecialchars(urlencode($story['url']), ENT_QUOTES)
           . df_readtok_qs((string)$story['url'], true) . '">'
           . e($title) . '</a></h2>';
    } else {
        echo '<h2>' . e($title) . '</h2>';
    }
    echo '<p><font size="1" color="' . df_muted_color() . '">' . (int)($story['score'] ?? 0)
       . ' points by ' . e((string)($story['by'] ?? '?')) . ' &middot; ' . hn_ago((int)($story['time'] ?? 0))
       . ' &middot; ' . (int)($story['descendants'] ?? 0) . ' comments</font></p>';
    if (!empty($story['text'])) echo '<p>' . hn_sanitize((string)$story['text']) . '</p>';
    echo '<hr>';

    // Level by level (top-level comments first), each level fetched in parallel
    // batches (hn_items) under the time budget and comment cap. Was one item at
    // a time: a cold 1,946-comment thread showed only ~25 comments in 8 s.
    // Deleted/dead comments keep a placeholder so their replies still show.
    $items = [];
    $level = array_map('intval', $story['kids'] ?? []);
    $deadline = microtime(true) + HN_BUDGET;
    $truncated = false;
    while ($level) {
        $room = HN_MAX_COMMENTS - count($items);
        if ($room <= 0 || microtime(true) >= $deadline) { $truncated = true; break; }
        if (count($level) > $room) { $level = array_slice($level, 0, $room); $truncated = true; }
        $got = hn_items($level, $deadline);
        $next = [];
        foreach ($level as $cid) {
            if (!isset($got[$cid])) { $truncated = true; continue; }
            $items[$cid] = $got[$cid];
            foreach ($got[$cid]['kids'] ?? [] as $k) $next[] = (int)$k;
        }
        $level = $next;
    }
    if (!$items) { echo '<p><i>No comments yet.</i></p>'; return; }
    foreach (($story['kids'] ?? []) as $k) echo hn_render((int)$k, $items, 0);
    $total = (int)($story['descendants'] ?? 0);
    $shown = count(array_filter($items, fn($it) => empty($it['deleted']) && empty($it['dead'])));
    if ($truncated || $shown < $total) {
        echo '<hr><p><font size="1">(showing ' . $shown . ' of ' . max($total, $shown)
           . ' comments -- reload to load more)</font></p>';
    }
}

// Several HN items at once: cache hits first, then the misses in parallel
// batches of HN_PARALLEL with curl_multi -- the same pinned-IP, validated fetch
// as df_fetch_once (the API is one fixed host, validated once), cached under
// http_get_cached's own key so hn_item() and this share entries. Returns
// [id => item]; ids that failed or ran past $deadline are simply absent.
function hn_items(array $ids, float $deadline): array {
    $out = []; $miss = [];
    foreach ($ids as $id) {
        $id = (int)$id;
        if ($id <= 0) continue;
        $c = df_cache_get('raw:' . HN_API . '/item/' . $id . '.json', 600);
        $d = $c !== null ? @unserialize($c, ['allowed_classes' => false]) : null;
        $j = is_array($d) ? json_decode((string)($d['body'] ?? ''), true) : null;
        if (is_array($j)) $out[$id] = $j; else $miss[] = $id;
    }
    if (!$miss || !function_exists('curl_multi_init')) {
        foreach ($miss as $id) {                       // no curl_multi: the old serial path
            if (microtime(true) >= $deadline) break;
            if (($it = hn_item($id)) !== null) $out[$id] = $it;
        }
        return $out;
    }
    $t = df_validate_url(HN_API . '/item/0.json');
    if ($t === null) return $out;
    foreach (array_chunk($miss, HN_PARALLEL) as $batch) {
        $left = $deadline - microtime(true);
        if ($left <= 0.2) break;
        $mh = curl_multi_init(); $hs = [];
        foreach ($batch as $id) {
            $url = HN_API . '/item/' . $id . '.json';
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL => $url, CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_TIMEOUT_MS => (int)($left * 1000), CURLOPT_CONNECTTIMEOUT => 5,
                CURLOPT_USERAGENT => DUCKFIND_UA, CURLOPT_ENCODING => '',
                CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
                CURLOPT_RESOLVE => [$t['host'] . ':' . $t['port'] . ':' . $t['ip']],   // pinned, as df_fetch_once
                CURLOPT_MAXFILESIZE => 1000000,
            ]);
            curl_multi_add_handle($mh, $ch);
            $hs[$id] = $ch;
        }
        do {
            $st = curl_multi_exec($mh, $running);
            if ($running) curl_multi_select($mh, 0.2);
        } while ($running && $st === CURLM_OK && microtime(true) < $deadline);
        foreach ($hs as $id => $ch) {
            $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $body = (string)curl_multi_getcontent($ch);
            curl_multi_remove_handle($mh, $ch);
            $r = ['body' => $body, 'ctype' => (string)curl_getinfo($ch, CURLINFO_CONTENT_TYPE),
                  'status' => $code, 'url' => HN_API . '/item/' . $id . '.json'];
            $j = $code === 200 ? json_decode($body, true) : null;
            if (is_array($j)) {
                $out[$id] = $j;
                if (df_cacheable_response($r)) df_cache_put('raw:' . $r['url'], serialize($r));
            }
        }
        curl_multi_close($mh);
    }
    return $out;
}

// Render one comment and its loaded descendants; indent with <dl><dd> (left
// margin only, unlike blockquote, which also eats the right margin) and stop
// indenting past HN_INDENT_CAP so deep chains don't run off a narrow screen.
// A deleted or dead comment shows as [deleted] but keeps its replies.
function hn_render(int $id, array &$items, int $depth): string {
    $it = $items[$id] ?? null;
    if (!$it) return '';
    // Byline and body are separate <p> blocks, not nested -- hn_walk() already
    // emits its own <p> tags for paragraph breaks inside a multi-paragraph
    // comment (HN's raw HTML often has them), so wrapping the whole thing in
    // one more outer <p> (the old behavior) produced invalid nested
    // </p></p> sequences. Confirmed live on real multi-paragraph comments
    // (2026-10-09).
    $gone = !empty($it['deleted']) || !empty($it['dead']);
    $out = $gone
         ? '<p><font size="1" color="' . df_muted_color() . '"><i>[deleted]</i></font></p>'
         : '<p><font size="1" color="' . df_muted_color() . '"><b>' . e((string)($it['by'] ?? '?'))
           . '</b> &middot; ' . hn_ago((int)($it['time'] ?? 0)) . '</font></p>'
           . hn_sanitize((string)($it['text'] ?? ''));
    $kids = array_filter($it['kids'] ?? [], fn($k) => isset($items[(int)$k]));
    if ($kids) {
        $indent = $depth < HN_INDENT_CAP;
        if ($indent) $out .= '<dl><dd>';
        foreach ($kids as $k) $out .= hn_render((int)$k, $items, $depth + 1);
        if ($indent) $out .= '</dd></dl>';
    }
    return $out;
}

// Cached fetch of one HN item.
function hn_item(int $id): ?array {
    if ($id <= 0) return null;
    $r = http_get_cached(HN_API . '/item/' . $id . '.json', 600);
    if ($r === null) return null;
    $j = json_decode($r['body'], true);
    return is_array($j) ? $j : null;
}

function hn_ago(int $ts): string {
    if ($ts <= 0) return '';
    $d = max(0, time() - $ts);
    if ($d < 3600)  return (int)($d / 60) . 'm ago';
    if ($d < 86400) return (int)($d / 3600) . 'h ago';
    return (int)($d / 86400) . 'd ago';
}

// Sanitise HN comment HTML to a vintage-safe allowlist. HN already limits tags,
// but we rebuild from the DOM (never trust) — keeping p/i/b/code, unwrapping the
// rest to text, and routing every http(s) link through the reader.
function hn_sanitize(string $html): string {
    $html = trim($html);
    if ($html === '') return '';
    $doc = new DOMDocument();
    @$doc->loadHTML('<?xml encoding="UTF-8"?><div>' . $html . '</div>',
                    LIBXML_NONET | LIBXML_NOERROR | LIBXML_NOWARNING);
    $div = $doc->getElementsByTagName('div')->item(0);
    if (!$div) return e(strip_tags($html));

    // A real HN comment shape: a bare lead-in line (often a quoted "> ..."
    // reply) before the comment's first explicit <p> -- that run was
    // previously emitted completely unwrapped, running flush against the
    // byline with no paragraph spacing while every later explicit <p> in the
    // same comment got proper spacing. Group any run of non-<p> top-level
    // content into its own <p>, same as an explicit one gets. Confirmed live
    // 2026-10-09 (Derek: "the formatting for some might be a little not
    // pretty").
    $out = ''; $buf = '';
    foreach ($div->childNodes as $c) {
        $tag = $c->nodeType === XML_ELEMENT_NODE ? strtolower($c->nodeName) : '';
        if ($tag === 'p' || $tag === 'pre') {
            if ($buf !== '') { $out .= hn_quote_wrap($buf); $buf = ''; }
            $out .= hn_render_child($c);
        } else {
            $buf .= hn_render_child($c);
        }
    }
    if ($buf !== '') $out .= hn_quote_wrap($buf);
    return $out;
}

// A single paragraph's rendered inner HTML, as a <p> -- quoted-reply
// paragraphs (HN's own "&gt; quoted text" convention, never styled distinctly
// before) get italicised so a quote reads as visually distinct from the
// commenter's own words, same spirit as a real forum's blockquote styling.
function hn_quote_wrap(string $inner): string {
    return str_starts_with(ltrim($inner), '&gt;')
        ? '<p><i>' . $inner . '</i></p>'
        : '<p>' . $inner . '</p>';
}

function hn_walk(DOMNode $node): string {
    $out = '';
    foreach ($node->childNodes as $c) { $out .= hn_render_child($c); }
    return $out;
}

// Render exactly one DOM child (text or element) to its sanitised HTML.
function hn_render_child(DOMNode $c): string {
    if ($c->nodeType === XML_TEXT_NODE) return e($c->nodeValue);
    if ($c->nodeType !== XML_ELEMENT_NODE) return '';
    $tag = strtolower($c->nodeName);
    $inner = hn_walk($c);
    if ($tag === 'a') {
        $href = $c->getAttribute('href');
        return preg_match('#^https?://#i', $href)
            ? '<a href="/read.php?url=' . htmlspecialchars(urlencode($href), ENT_QUOTES) . df_readtok_qs($href, true) . '">'   // signed
              . ($inner !== '' ? $inner : e($href)) . '</a>'
            : $inner;
    }
    if ($tag === 'p')                      return hn_quote_wrap($inner);
    if ($tag === 'i' || $tag === 'em')     return '<i>' . $inner . '</i>';
    if ($tag === 'b' || $tag === 'strong') return '<b>' . $inner . '</b>';
    // code blocks keep their line breaks: <pre> with the text as-is (an inner
    // <code> is just unwrapped); inline <code> stays <tt>
    if ($tag === 'pre')                    return '<pre>' . e($c->textContent) . '</pre>';
    if ($tag === 'code')                   return '<tt>' . $inner . '</tt>';
    return $inner;   // unwrap unknown
}
