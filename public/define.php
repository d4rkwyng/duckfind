<?php
// DuckFind dictionary — plain-HTML definitions via the free dictionaryapi.dev.
require __DIR__ . '/lib.php';
if (!df_rate('search')) df_rate_block();
header('Content-Type: text/html; charset=iso-8859-1');

$word = trim(df_input('q'));

echo page_head(DUCKFIND_NAME . ' - define' . ($word !== '' ? ': ' . $word : ''));
echo '<form action="/define.php" method="get">' . df_brand_link() . '&nbsp;&nbsp;'
   . 'Define: <input type="text" name="q" size="24" value="' . e($word) . '">&nbsp;'
   . '<input type="submit" value="Look up"></form><hr>';

if ($word === '') {
    echo '<p>Enter a word above to look up its definition.</p>' . page_foot(); exit;
}

$result = define_lookup($word);
if ($result['found'] === null) {
    echo '<p>The dictionary service is temporarily unavailable. Please try again shortly. '
       . '[<a href="/define.php?q=' . e(urlencode($word)) . '">try again</a>]</p>' . page_foot();
    exit;
}
if ($result['found'] === false) {
    echo '<p>No definition found for <b>' . e($word) . '</b>. '
       . '[<a href="/?q=' . e(urlencode('define ' . $word)) . '">search instead</a>]</p>' . page_foot();
    exit;
}

$entry = $result['data'][0];
echo '<h2>' . e($entry['word'] ?? $word) . '</h2>';
foreach (($entry['phonetics'] ?? []) as $ph) {
    if (!empty($ph['text'])) { echo '<p><i>' . e($ph['text']) . '</i></p>'; break; }
}

foreach ($entry['meanings'] as $m) {
    echo '<p><b>' . e($m['partOfSpeech'] ?? '') . '</b></p><ol>';
    foreach (array_slice($m['definitions'] ?? [], 0, 5) as $d) {
        echo '<li>' . e($d['definition'] ?? '');
        if (!empty($d['example'])) echo '<br><font size="1"><i>"' . e($d['example']) . '"</i></font>';
        echo '</li>';
    }
    echo '</ol>';
    if (!empty($m['synonyms'])) {
        echo '<p><font size="1"><b>Synonyms:</b> ' . e(implode(', ', array_slice($m['synonyms'], 0, 8)))
           . '</font></p>';
    }
}
echo '<p><font size="1">Source: <a href="https://dictionaryapi.dev/">dictionaryapi.dev</a></font></p>';
echo page_foot();

// dictionaryapi.dev is occasionally flaky (confirmed live 2026-10-09: Cloudflare
// 522/404 origin errors flapping on ordinary words like "apple") -- same
// unpredictable all-or-nothing shape as Gutendex (see ebook.php's
// gutendex_get()). Retry a few times before concluding anything, and
// distinguish a genuine "no definitions found" (the API's own 404 JSON body,
// which always carries a "title" field) from a fetch failure (network error,
// 5xx, or a malformed/non-JSON body) so a real word isn't told it doesn't
// exist just because the upstream hiccuped.
function define_lookup(string $word): array {
    $url = 'https://api.dictionaryapi.dev/api/v2/entries/en/' . urlencode($word);
    for ($i = 0; $i < 3; $i++) {
        if ($i > 0) usleep(400000);
        $r = http_get($url, 3000000, '', null, 4);
        if ($r === null) continue;                              // network-level failure, retry
        $data = json_decode($r['body'], true);
        if (($r['status'] ?? 0) === 404 && is_array($data) && isset($data['title'])) {
            return ['found' => false, 'data' => null];           // the API's own real "not found"
        }
        if (is_array($data) && !empty($data[0]['meanings'])) {
            return ['found' => true, 'data' => $data];
        }
        // anything else (5xx, malformed body, unexpected shape) -- retry
    }
    return ['found' => null, 'data' => null];                    // genuinely couldn't tell after retries
}
