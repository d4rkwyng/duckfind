<?php
// DuckFind translate — `!translate bonjour mon ami to english`. Translation is
// done by Microsoft Translator through DuckDuckGo's anonymizing proxy (the
// same translation module DDG shows on its results page), so no account, no
// API key, and the visitor's address never reaches Microsoft. Unofficial
// endpoint, same fragility class as our DDG search scraping: fetch a vqd
// token from the homepage, POST the text to translation.js.
require __DIR__ . '/lib.php';

if (!df_rate('search')) df_rate_block();
header('Content-Type: text/html; charset=iso-8859-1');

define('TR_MAX', 1000);   // characters per request

$langs = [
    'english' => 'en', 'french' => 'fr', 'spanish' => 'es', 'german' => 'de',
    'italian' => 'it', 'portuguese' => 'pt', 'dutch' => 'nl', 'swedish' => 'sv',
    'norwegian' => 'nb', 'danish' => 'da', 'finnish' => 'fi', 'polish' => 'pl',
    'czech' => 'cs', 'hungarian' => 'hu', 'romanian' => 'ro', 'greek' => 'el',
    'russian' => 'ru', 'ukrainian' => 'uk', 'turkish' => 'tr', 'arabic' => 'ar',
    'hebrew' => 'he', 'hindi' => 'hi', 'thai' => 'th', 'vietnamese' => 'vi',
    'indonesian' => 'id', 'chinese' => 'zh-Hans', 'japanese' => 'ja', 'korean' => 'ko',
];

// Accept either form fields (text + to) or a single bang-style query:
// "une baguette s'il vous plait to english" — the last " to <language>" wins.
$text = trim(df_input('text'));
$to   = trim((string)($_GET['to'] ?? ''));
if ($text === '') {
    $q = trim(df_input('q'));
    if ($q !== '' && preg_match('/^(.*)\s+to\s+([a-z][a-z\-]{1,10})$/is', $q, $m)
        && (isset($langs[strtolower($m[2])]) || in_array(strtolower($m[2]), $langs, true))) {
        $text = trim($m[1]);
        $to   = strtolower($m[2]);
    } else {
        $text = $q;                 // no target named: translate INTO English
        $to   = 'en';
    }
}
$to = $langs[strtolower($to)] ?? $to;
if (!in_array($to, $langs, true)) $to = 'en';
$text = mb_substr($text, 0, TR_MAX);

echo page_head(DUCKFIND_NAME . ' - translate');
echo '<form action="/translate.php" method="get"><a href="/"><b>' . DUCKFIND_NAME . '</b></a>'
   . '&nbsp;&nbsp;Translate:<br><textarea name="text" rows="3" cols="40">' . e($text) . '</textarea><br>'
   . 'into <select name="to">';
foreach ($langs as $lname => $lcode) {
    echo '<option value="' . $lcode . '"' . ($lcode === $to ? ' selected' : '') . '>'
       . ucfirst($lname) . '</option>';
}
echo '</select>&nbsp;<input type="submit" value="Quack!"></form><hr>';

if ($text === '') {
    echo '<p>Type or paste text above (any language &mdash; it is auto-detected), pick a '
       . 'target language, and go. Or use the shortcut: '
       . '<tt>!translate bonjour mon ami to english</tt></p>';
    echo df_translate_credit();
    echo page_foot(); exit;
}

$out = df_ddg_translate($text, $to);
if ($out === null) {
    echo '<p><b>Translation is temporarily unavailable.</b> Please try again in a moment.</p>';
} else {
    $fromName = array_search(strtolower((string)($out['detected_language'] ?? '')), $langs, true);
    echo '<p><font size="1">' . ($fromName !== false ? ucfirst($fromName) : 'Detected '
       . e((string)($out['detected_language'] ?? '?'))) . ' &rarr; '
       . ucfirst((string)array_search($to, $langs, true)) . ':</font></p>';
    echo '<p><font size="4"><b>' . nl2br(e((string)$out['translated'])) . '</b></font></p>';
    echo df_translate_credit();
}
echo page_foot();

function df_translate_credit(): string {
    return '<p><font size="1">Translations by Microsoft Translator via DuckDuckGo&#39;s '
         . 'anonymizing proxy &mdash; your address never reaches Microsoft, and '
         . DUCKFIND_NAME . ' keeps no record of what you translate.</font></p>';
}

// vqd tokens come from the DDG homepage and stay valid a while; cache one and
// refresh once on failure rather than hitting the homepage per translation.
function df_ddg_vqd(bool $fresh = false): ?string {
    if (!$fresh && ($v = df_cache_get('ddgvqd', 600)) !== null && $v !== '') return $v;
    $r = http_get('https://duckduckgo.com/?q=translate');
    if ($r === null || !preg_match('/vqd="?([0-9][0-9-]+)/', $r['body'], $m)) return null;
    df_cache_put('ddgvqd', $m[1]);
    return $m[1];
}

function df_ddg_translate(string $text, string $to): ?array {
    foreach ([false, true] as $fresh) {
        $vqd = df_ddg_vqd($fresh);
        if ($vqd === null) continue;
        $r = http_get('https://duckduckgo.com/translation.js?vqd=' . urlencode($vqd)
            . '&query=translate&to=' . urlencode($to), 300000, '', $text);
        $j = $r !== null ? json_decode($r['body'], true) : null;
        if (isset($j['translated'])) return $j;
    }
    return null;
}
