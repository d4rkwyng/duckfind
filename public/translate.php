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
// "une baguette s'il vous plait to english" -- the last " to <language NAME>"
// wins. Names only in the bang form: two-letter codes are ordinary English
// words ("I am looking forward to it" was being translated into Italian,
// 2026-11-12). The form's select still sends codes.
[$text, $to, $badTo] = tr_parse_request(trim(df_input('text')), trim(df_str($_GET['to'] ?? '')),
                                        trim(df_input('q')), $langs);
$text = mb_substr($text, 0, TR_MAX);

echo page_head(DUCKFIND_NAME . ' - translate');
echo '<form action="/translate.php" method="get">' . df_brand_link() . ''
   . '&nbsp;&nbsp;Translate:<br><textarea name="text" rows="3" cols="40">' . e($text) . '</textarea><br>'
   . 'into <select name="to">';
foreach ($langs as $lname => $lcode) {
    echo '<option value="' . $lcode . '"' . ($lcode === $to ? ' selected' : '') . '>'
       . ucfirst($lname) . '</option>';
}
echo '</select>&nbsp;<input type="submit" value="Quack!"></form><hr>';

if ($badTo !== '') {
    echo '<p><b>Unknown language: ' . e($badTo) . '.</b> Pick one from the list above.</p>';
    echo df_translate_credit();
    echo page_foot(); exit;
}
if ($text === '') {
    echo '<p>Type or paste text above (any language -- it is auto-detected), pick a '
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
       . e((string)($out['detected_language'] ?? '?'))) . ' -&gt; '
       . ucfirst((string)array_search($to, $langs, true)) . ':</font></p>';
    echo '<p><font size="4"><b>' . nl2br(e((string)$out['translated']), false) . '</b></font></p>';
    if (strtolower((string)($out['detected_language'] ?? '')) === strtolower($to)) {
        // e.g. "hello to klingon": no known language named, so it went into English
        echo '<p><font size="1">That text is already in ' . ucfirst((string)array_search($to, $langs, true))
           . '. To translate into another language, end with <tt>to</tt> and a language name, '
           . 'e.g. <tt>!translate good morning to french</tt>.</font></p>';
    }
    echo df_translate_credit();
}
echo page_foot();

function df_translate_credit(): string {
    return '<p><font size="1">Translations by Microsoft Translator via DuckDuckGo&#39;s '
         . 'anonymizing proxy -- your address never reaches Microsoft, and '
         . DUCKFIND_NAME . ' keeps no record of what you translate.</font></p>';
}

// vqd tokens come from the DDG homepage and stay valid a while; cache one and
// refresh once on failure rather than hitting the homepage per translation.
function df_ddg_vqd(bool $fresh = false): ?string {
    if (!$fresh && ($v = df_cache_get('ddgvqd', 600)) !== null && $v !== '') return $v;
    if (df_ddg_backoff_remaining('translate') > 0) return null;   // DDG blocked us: wait
    $r = http_get('https://duckduckgo.com/?q=translate');
    if (df_ddg_is_block($r)) { df_ddg_backoff_hit('translate'); return null; }
    if ($r === null || !preg_match('/vqd="?([0-9][0-9-]+)/', $r['body'], $m)) return null;
    df_cache_put('ddgvqd', $m[1]);
    return $m[1];
}

// Both DDG requests here (the vqd homepage and translation.js) respect the
// 'translate' endpoint backoff (lib.php): a block answer starts it, a real
// translation clears it, and while it runs no request is made at all.
function df_ddg_translate(string $text, string $to): ?array {
    foreach ([false, true] as $fresh) {
        if (df_ddg_backoff_remaining('translate') > 0) return null;
        $vqd = df_ddg_vqd($fresh);
        if ($vqd === null) continue;
        $r = http_get('https://duckduckgo.com/translation.js?vqd=' . urlencode($vqd)
            . '&query=translate&to=' . urlencode($to), 300000, '', $text);
        if (df_ddg_is_block($r)) { df_ddg_backoff_hit('translate'); return null; }
        $j = $r !== null ? json_decode($r['body'], true) : null;
        if (isset($j['translated'])) { df_ddg_backoff_clear('translate'); return $j; }
    }
    return null;
}

// -> [text, target code, unknown target ('' when fine)]. $langs maps lowercase
// names to codes. The form sends text + to (a code or name, any case); the
// bang sends q, where only a trailing " to <name>" picks the target and
// anything else is translated into English.
function tr_parse_request(string $text, string $to, string $q, array $langs): array {
    $codes = [];
    foreach ($langs as $code) $codes[strtolower($code)] = $code;
    if ($text === '') {
        if ($q !== '' && preg_match('/^(.*\S)\s+to\s+([a-z]+)$/is', $q, $m) && isset($langs[strtolower($m[2])])) {
            return [mb_substr(trim($m[1]), 0, TR_MAX), $langs[strtolower($m[2])], ''];
        }
        return [mb_substr($q, 0, TR_MAX), 'en', ''];   // no language named: into English
    }
    $k = strtolower($to);
    if ($to === '' ) return [mb_substr($text, 0, TR_MAX), 'en', ''];
    if (isset($langs[$k])) return [mb_substr($text, 0, TR_MAX), $langs[$k], ''];
    if (isset($codes[$k])) return [mb_substr($text, 0, TR_MAX), $codes[$k], ''];
    return [mb_substr($text, 0, TR_MAX), 'en', $to];
}
