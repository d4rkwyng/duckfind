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
define('HN_INDENT_CAP', 6);      // stop nesting past this depth (narrow screens)
define('HN_BUDGET', 8.0);        // seconds spent fetching a thread's comments

$lists = ['top' => 'topstories', 'new' => 'newstories', 'best' => 'beststories',
          'ask' => 'askstories', 'show' => 'showstories'];
$id   = (int)($_GET['id'] ?? 0);
$list = isset($_GET['list'], $lists[$_GET['list']]) ? $_GET['list'] : 'top';

echo page_head(DUCKFIND_NAME . ' - Hacker News' . ($id > 0 ? '' : ' (' . $list . ')'));
echo '<form action="/" method="get"><a href="/"><b>' . DUCKFIND_NAME . '</b></a>&nbsp;&nbsp;'
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
    echo '<ol>';
    foreach ($ids as $sid) {
        $it = hn_item((int)$sid);
        if (!$it || empty($it['title'])) continue;
        $thread = '/hn.php?id=' . (int)$sid;
        $target = !empty($it['url']) ? '/read.php?url=' . htmlspecialchars(urlencode($it['url']), ENT_QUOTES)
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
        echo '<h2><a href="/read.php?url=' . htmlspecialchars(urlencode($story['url']), ENT_QUOTES) . '">'
           . e($title) . '</a></h2>';
    } else {
        echo '<h2>' . e($title) . '</h2>';
    }
    echo '<p><font size="1" color="' . df_muted_color() . '">' . (int)($story['score'] ?? 0)
       . ' points by ' . e((string)($story['by'] ?? '?')) . ' &middot; ' . hn_ago((int)($story['time'] ?? 0))
       . ' &middot; ' . (int)($story['descendants'] ?? 0) . ' comments</font></p>';
    if (!empty($story['text'])) echo '<p>' . hn_sanitize((string)$story['text']) . '</p>';
    echo '<hr>';

    // breadth-first fetch (top-level comments first) under budget + cap
    $items = [];
    $queue = $story['kids'] ?? [];
    $deadline = microtime(true) + HN_BUDGET;
    $truncated = false;
    while ($queue) {
        if (count($items) >= HN_MAX_COMMENTS || microtime(true) >= $deadline) { $truncated = true; break; }
        $cid = (int)array_shift($queue);
        $it = hn_item($cid);
        if (!$it || !empty($it['deleted']) || !empty($it['dead'])) continue;
        $items[$cid] = $it;
        foreach ($it['kids'] ?? [] as $k) $queue[] = $k;
    }
    if (!$items) { echo '<p><i>No comments yet.</i></p>'; return; }
    foreach (($story['kids'] ?? []) as $k) echo hn_render((int)$k, $items, 0);
    if ($truncated) {
        echo '<hr><p><font size="1">(the deeper/rest of this thread was not loaded to keep the page '
           . 'quick -- open individual replies on <a href="https://news.ycombinator.com/item?id='
           . $id . '">HN</a>)</font></p>';
    }
}

// Render one comment and its loaded descendants; indent via nested blockquote,
// capped so deep chains don't run off a narrow screen.
function hn_render(int $id, array &$items, int $depth): string {
    $it = $items[$id] ?? null;
    if (!$it) return '';
    $out = '<p><font size="1" color="' . df_muted_color() . '"><b>' . e((string)($it['by'] ?? '?'))
         . '</b> &middot; ' . hn_ago((int)($it['time'] ?? 0)) . '</font><br>'
         . hn_sanitize((string)($it['text'] ?? '')) . '</p>';
    $kids = array_filter($it['kids'] ?? [], fn($k) => isset($items[(int)$k]));
    if ($kids) {
        $indent = $depth < HN_INDENT_CAP;
        if ($indent) $out .= '<blockquote>';
        foreach ($kids as $k) $out .= hn_render((int)$k, $items, $depth + 1);
        if ($indent) $out .= '</blockquote>';
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
    // e() inside hn_walk already numeric-entity-encodes non-ASCII text
    return $div ? hn_walk($div) : e(strip_tags($html));
}

function hn_walk(DOMNode $node): string {
    $out = '';
    foreach ($node->childNodes as $c) {
        if ($c->nodeType === XML_TEXT_NODE) { $out .= e($c->nodeValue); continue; }
        if ($c->nodeType !== XML_ELEMENT_NODE) continue;
        $tag = strtolower($c->nodeName);
        $inner = hn_walk($c);
        if ($tag === 'a') {
            $href = $c->getAttribute('href');
            $out .= preg_match('#^https?://#i', $href)
                ? '<a href="/read.php?url=' . htmlspecialchars(urlencode($href), ENT_QUOTES) . '">'
                  . ($inner !== '' ? $inner : e($href)) . '</a>'
                : $inner;
        } elseif ($tag === 'p')                        { $out .= '<p>' . $inner . '</p>';
        } elseif ($tag === 'i' || $tag === 'em')       { $out .= '<i>' . $inner . '</i>';
        } elseif ($tag === 'b' || $tag === 'strong')   { $out .= '<b>' . $inner . '</b>';
        } elseif ($tag === 'pre' || $tag === 'code')   { $out .= '<tt>' . $inner . '</tt>';
        } else                                         { $out .= $inner; }   // unwrap unknown
    }
    return $out;
}
