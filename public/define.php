<?php
// DuckFind dictionary — plain-HTML definitions via the free dictionaryapi.dev.
require __DIR__ . '/lib.php';
if (!df_rate('search')) df_rate_block();
header('Content-Type: text/html; charset=iso-8859-1');

$word = trim(df_input('q'));

echo page_head(DUCKFIND_NAME . ' define' . ($word !== '' ? ' - ' . $word : ''));
echo '<form action="/define.php" method="get"><a href="/"><b>' . DUCKFIND_NAME . '</b></a>&nbsp;&nbsp;'
   . 'Define: <input type="text" name="q" size="24" value="' . e($word) . '">&nbsp;'
   . '<input type="submit" value="Look up"></form><hr>';

if ($word === '') {
    echo '<p>Enter a word above to look up its definition.</p>' . page_foot(); exit;
}

$r = http_get('https://api.dictionaryapi.dev/api/v2/entries/en/' . urlencode($word));
$data = $r ? json_decode($r['body'], true) : null;

if (!is_array($data) || empty($data[0]['meanings'])) {
    echo '<p>No definition found for <b>' . e($word) . '</b>. '
       . '[<a href="/?q=' . e(urlencode('define ' . $word)) . '">search instead</a>]</p>' . page_foot();
    exit;
}

$entry = $data[0];
echo '<h2>' . e($entry['word'] ?? $word) . '</h2>';
foreach (($entry['phonetics'] ?? []) as $ph) {
    if (!empty($ph['text'])) { echo '<p><i>' . e($ph['text']) . '</i></p>'; break; }
}

foreach ($entry['meanings'] as $m) {
    echo '<p><b>' . e($m['partOfSpeech'] ?? '') . '</b></p><ol>';
    foreach (array_slice($m['definitions'] ?? [], 0, 5) as $d) {
        echo '<li>' . e($d['definition'] ?? '');
        if (!empty($d['example'])) echo '<br><font size="1"><i>&ldquo;' . e($d['example']) . '&rdquo;</i></font>';
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
