<?php
// DuckFind ebook reader — search and read full Project Gutenberg books, paged
// into vintage-friendly chunks. Same family as wiki.php and define.php: a
// thin wrapper around a clean, purpose-fit API rather than scraping HTML.
// Catalog search/metadata comes from Gutendex (gutendex.com), a free
// community-run JSON index of Project Gutenberg -- the official site has no
// JSON API of its own, only an HTML search UI. The actual book text is
// fetched straight from gutenberg.org itself via the URL Gutendex's own
// metadata points at, so Gutendex never sees or serves the book content,
// only the catalog lookup.
//
// A full novel (occasionally 3+ MB of plain text) isn't something a vintage
// browser should receive as one HTML page -- it's split into pages of a few
// thousand characters, snapped to paragraph boundaries, with the whole book
// fetched/cleaned once and cached (so page 2..N of a long book never re-hits
// gutenberg.org). The Project Gutenberg legal boilerplate wrapped around
// every text file's start/end is stripped so what's shown is just the book.
require __DIR__ . '/lib.php';
if (!df_rate('read')) df_rate_block();

define('EBOOK_FETCH_CAP', 6000000);   // covers virtually every real PG text (the longest run a few MB)
define('EBOOK_PAGE_CHARS', 3000);     // target chars per rendered page
define('EBOOK_PAGE_PARAS', 20);       // and a paragraph-count cap -- see ebook_paginate()

$q   = trim(df_input('q'));
$id  = (int)($_GET['id'] ?? 0);
$pNo = max(1, (int)($_GET['p'] ?? 1));

header('Content-Type: text/html; charset=iso-8859-1');

if ($id > 0) {
    ebook_show($id, $pNo);
    exit;
}

echo page_head(DUCKFIND_NAME . ' - ebooks' . ($q !== '' ? ': ' . $q : ''));
echo '<form action="/ebook.php" method="get">' . df_brand_link() . '&nbsp;&nbsp;'
   . 'Book or author: <input type="text" name="q" size="24" value="' . e($q) . '">&nbsp;'
   . '<input type="submit" value="Search"></form><hr>';

if ($q === '') {
    echo '<p>Search over 75,000 free public-domain ebooks from Project Gutenberg and '
       . 'read them right here, paged for a vintage screen -- no downloads, no e-reader '
       . 'app.</p>';
    echo '<p><font size="1">Try: '
       . '<a href="/ebook.php?q=moby+dick">Moby Dick</a> &middot; '
       . '<a href="/ebook.php?q=sherlock+holmes">Sherlock Holmes</a> &middot; '
       . '<a href="/ebook.php?q=jane+austen">Jane Austen</a></font></p>';
    echo page_foot();
    exit;
}

$results = ebook_search($q);
if ($results === null) {
    echo '<p><b>The ebook catalog is temporarily unavailable.</b> Please try again '
       . 'shortly.</p>' . page_foot();
    exit;
}
if (!$results) {
    echo '<p>No books found for <b>' . e($q) . '</b>.</p>' . page_foot();
    exit;
}

echo "<p>\n";
foreach ($results as $b) {
    $title   = (string)($b['title'] ?? 'Untitled');
    $authors = implode(', ', array_map(fn($a) => (string)($a['name'] ?? ''), $b['authors'] ?? []));
    $lang    = implode(',', $b['languages'] ?? []);
    echo '<a href="/ebook.php?id=' . (int)($b['id'] ?? 0) . '">' . e($title) . '</a>'
       . ($authors !== '' ? ' <font size="1" color="' . df_muted_color() . '">by ' . e($authors) . '</font>' : '')
       . ($lang !== '' && $lang !== 'en' ? ' <font size="1">[' . e($lang) . ']</font>' : '')
       . "<br>\n";
}
echo "</p>\n" . page_foot();
exit;

// Gutendex is a free, unofficial community API with no SLA. Real, repeated
// live testing (2026-10-07/08) found its search/lookup endpoints fail in an
// unpredictable, all-or-nothing way -- a request either comes back fast
// (well under a second) or hangs for the full timeout with nothing, never
// "slow but working". A single retry wasn't enough odds (Derek hit two
// failures in a row live); several quick attempts with a short per-try
// timeout catches far more of the fast-success windows than one or two
// attempts at the default (12s) timeout, for a similar worst-case total wait.
function gutendex_get(string $url): ?array {
    for ($i = 0; $i < 3; $i++) {
        if ($i > 0) usleep(400000);
        $r = http_get($url, 2000000, DUCKFIND_UA, null, 4);
        if ($r !== null && ($r['status'] ?? 200) < 400) return $r;
    }
    return null;
}

// --- search: cache Gutendex's own response shape briefly (catalog rarely changes) --
function ebook_search(string $q): ?array {
    $key = 'ebooksearch:' . mb_strtolower($q);
    if (($c = df_cache_get($key, 86400)) !== null) {
        $d = json_decode($c, true);
        return is_array($d) ? $d : null;
    }
    $r = gutendex_get('https://gutendex.com/books/?search=' . urlencode($q));
    if ($r === null) return null;
    $j = json_decode($r['body'], true);
    if (!is_array($j) || !isset($j['results'])) return null;
    df_cache_put($key, json_encode($j['results']));
    return $j['results'];
}

// --- one book: metadata (cached long -- static once published), text (cached
// long, cleaned once), then pagination computed fresh every view (cheap, and
// keeps page boundaries consistent if EBOOK_PAGE_CHARS is ever tuned) --------
function ebook_show(int $id, int $pNo): void {
    $meta = ebook_meta($id);
    if ($meta === null) {
        echo page_head(DUCKFIND_NAME . ' - ebooks', true)
           . '<p><b>Could not find that book.</b> [<a href="/ebook.php">search again</a>]</p>'
           . page_foot();
        return;
    }
    $title   = (string)($meta['title'] ?? 'Untitled');
    $authors = implode(', ', array_map(fn($a) => (string)($a['name'] ?? ''), $meta['authors'] ?? []));

    $text = ebook_text($id, $meta);
    if ($text === null) {
        echo page_head(DUCKFIND_NAME . ' - ' . $title, true)
           . '<p><b>' . e($title) . '</b> has no plain-text edition available to read here. '
           . '[<a href="/ebook.php">search again</a>]</p>' . page_foot();
        return;
    }

    $pages = ebook_paginate(ebook_paragraphs(ebook_strip_boilerplate($text)));
    $total = count($pages);
    $pNo   = min($pNo, $total);

    echo page_head(DUCKFIND_NAME . ' - ' . $title . ' (' . $pNo . '/' . $total . ')');
    echo '<form action="/ebook.php" method="get">' . df_brand_link() . '&nbsp;&nbsp;'
       . 'Book or author: <input type="text" name="q" size="24">&nbsp;'
       . '<input type="submit" value="Search"></form><hr>';
    echo '<h2>' . e($title) . '</h2>';
    if ($authors !== '') echo '<p><font size="1" color="' . df_muted_color() . '">by ' . e($authors) . '</font></p>';

    foreach ($pages[$pNo - 1] as $para) {
        echo '<p>' . e($para) . '</p>';
    }

    echo '<hr><p align="center">';
    if ($pNo > 1) echo '<a href="/ebook.php?id=' . $id . '&amp;p=' . ($pNo - 1) . '">&laquo; previous</a> &nbsp;&middot;&nbsp; ';
    echo 'page ' . $pNo . ' of ' . $total;
    if ($pNo < $total) echo ' &nbsp;&middot;&nbsp; <a href="/ebook.php?id=' . $id . '&amp;p=' . ($pNo + 1) . '">next &raquo;</a>';
    echo '</p>';
    echo '<p><font size="1">from <a href="https://www.gutenberg.org/ebooks/' . $id . '">Project Gutenberg</a>, '
       . 'public domain</font></p>';
    echo page_foot();
}

function ebook_meta(int $id): ?array {
    $key = 'ebookmeta:' . $id;
    if (($c = df_cache_get($key, 2592000)) !== null) {   // 30 days -- static once published
        $d = json_decode($c, true);
        return is_array($d) ? ($d ?: null) : null;
    }
    $r = gutendex_get('https://gutendex.com/books/' . $id . '/');
    if ($r === null) return null;
    $j = json_decode($r['body'], true);
    if (!is_array($j) || empty($j['title'])) return null;
    df_cache_put($key, json_encode($j));
    return $j;
}

// Picks the plain-text format URL out of Gutendex's own metadata (never
// guesses a gutenberg.org URL pattern directly -- those have changed shape
// over the years and Gutendex already did that work).
function ebook_text(int $id, array $meta): ?string {
    $key = 'ebooktext:' . $id;
    if (($c = df_cache_get($key, 2592000)) !== null) return $c;

    $formats = $meta['formats'] ?? [];
    $url = null;
    foreach ($formats as $mime => $u) {
        if (stripos((string)$mime, 'text/plain') === 0) { $url = $u; if (stripos((string)$mime, 'utf-8') !== false) break; }
    }
    if ($url === null) return null;

    $r = http_get((string)$url, EBOOK_FETCH_CAP, DUCKFIND_UA);
    if ($r === null || ($r['status'] ?? 200) >= 400 || $r['body'] === '') return null;
    $body = mb_check_encoding($r['body'], 'UTF-8') ? $r['body'] : mb_convert_encoding($r['body'], 'UTF-8', 'ISO-8859-1');
    df_cache_put($key, $body);
    return $body;
}

function ebook_strip_boilerplate(string $text): string {
    if (preg_match('/\*\*\*\s*START OF (?:THE|THIS) PROJECT GUTENBERG EBOOK\b.*?\*\*\*(.*)\*\*\*\s*END OF (?:THE|THIS) PROJECT GUTENBERG EBOOK\b/is', $text, $m)) {
        return trim($m[1]);
    }
    return trim($text);   // unrecognised wrapper -- show it all rather than guess and cut real content
}

function ebook_paragraphs(string $text): array {
    $out = [];
    foreach (preg_split('/\n\s*\n+/', $text) as $p) {
        $p = preg_replace('/\s+/', ' ', trim($p));
        if ($p !== '') $out[] = $p;
    }
    return $out;
}

// Greedy bin-pack into pages of ~EBOOK_PAGE_CHARS, never splitting a
// paragraph across pages. Also caps paragraphs per page -- a char-only limit
// badly misjudges a long table of contents (Moby Dick's real one is 135
// short one-line chapter titles): a few thousand characters' worth of those
// is ~100 list lines on one page, with the actual story shoved several pages
// deep. Capping paragraph count keeps any single page -- ToC, dialogue,
// prose -- to a sane number of visual chunks regardless of how short each
// one is, without needing to specifically detect "this is a table of
// contents" (which varies too much across books/transcribers to sniff
// reliably).
function ebook_paginate(array $paras): array {
    $pages = []; $cur = []; $len = 0;
    foreach ($paras as $p) {
        $cur[] = $p;
        $len += strlen($p);
        if ($len >= EBOOK_PAGE_CHARS || count($cur) >= EBOOK_PAGE_PARAS) { $pages[] = $cur; $cur = []; $len = 0; }
    }
    if ($cur) $pages[] = $cur;
    return $pages ?: [[]];
}
