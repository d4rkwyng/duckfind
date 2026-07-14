<?php
// DuckFind Ask — the !ai shortcut. Answers a question with Claude and renders
// the reply as plain HTML for vintage browsers. Optional and paid: it does
// nothing unless an API key is set in config.php. Bounded by a per-IP rate
// limit and a hard site-wide daily cap (see config.example.php).
require __DIR__ . '/lib.php';
header('Content-Type: text/html; charset=iso-8859-1');

$q = df_input('q');
$backSearch = fn() => '/?q=' . htmlspecialchars(urlencode($q), ENT_QUOTES);

if ($q === '') {
    echo page_head('Ask', true)
       . '<p>Ask a question, e.g. <tt>/ask.php?q=how tall is Mount Everest</tt>, '
       . 'or type <tt>!ai your question</tt> in the search box.</p>' . page_foot();
    exit;
}

$key = trim((string)df_cfg('ai_api_key', ''));
if ($key === '') {
    echo page_head('Ask', true)
       . '<h1>AI answers are not enabled</h1>'
       . '<p>This DuckFind has no AI key configured, so <tt>!ai</tt> is off.</p>'
       . '<p>[<a href="' . $backSearch() . '">search this instead</a>]</p>' . page_foot();
    exit;
}

if (!df_rate('ai')) df_rate_block();

// Hard site-wide daily ceiling — the cost cap. Checked before the call; a
// successful answer increments it (failed calls don't burn a slot).
$cap = (int)df_cfg('ai_daily_cap', 500);
if ($cap > 0 && df_daily_count('ai') >= $cap) {
    echo page_head('Ask', true)
       . '<h1>AI answers are maxed out for today</h1>'
       . '<p>To keep costs bounded, DuckFind caps AI answers per day and today\'s limit '
       . 'has been reached. Please try again tomorrow.</p>'
       . '<p>[<a href="' . $backSearch() . '">search this instead</a>]</p>' . page_foot();
    exit;
}

$answer = df_ai_ask($q, $key);
if ($answer !== null) df_daily_inc('ai');

echo page_head('Ask: ' . $q, true);
echo '<form action="/ask.php" method="get"><a href="/"><b>' . DUCKFIND_NAME . '</b></a>&nbsp;&nbsp;'
   . '<input type="text" name="q" size="30" value="' . e($q) . '">&nbsp;'
   . '<input type="submit" value="Ask"></form><hr>';
echo '<h1>' . e($q) . '</h1>';

if ($answer === null) {
    echo '<p><b>The AI answer could not be generated right now.</b> Please try again in a moment.</p>'
       . '<p>[<a href="' . $backSearch() . '">search this instead</a>]</p>';
} else {
    // plain text -> simple paragraphs (blank line separates; single newline -> <br>)
    foreach (preg_split('/\n{2,}/', trim($answer)) as $para) {
        $para = trim($para);
        if ($para !== '') echo '<p>' . nl2br(e($para)) . '</p>';
    }
    echo '<hr><p><font size="1" color="' . df_muted_color() . '">'
       . 'Answered by AI (Claude) &mdash; it can be wrong, so verify anything important. '
       . 'Your question was sent to Anthropic to generate this answer; DuckFind keeps no log of it. '
       . '[<a href="' . $backSearch() . '">web results</a>]</font></p>';
}
echo page_foot();

// Call the Anthropic Messages API and return the answer text, or null on any
// error. This is a fixed, trusted endpoint, so it's a direct HTTPS POST rather
// than the SSRF-guarded http_get (which is GET-only, for user-supplied URLs).
function df_ai_ask(string $question, string $key): ?string {
    if (!function_exists('curl_init')) return null;
    $sys = 'You are answering a search query for someone browsing on a vintage computer with a very '
         . 'old web browser. Answer concisely and directly in plain text only: no Markdown, no headings, '
         . 'no asterisks, no code fences, no tables, no emoji, and no URLs unless essential. Separate '
         . 'paragraphs with a blank line. If the question needs real-time data you do not have, say so '
         . 'in one sentence.';
    $payload = json_encode([
        'model'      => (string)df_cfg('ai_model', 'claude-haiku-4-5'),
        'max_tokens' => (int)df_cfg('ai_max_tokens', 500),
        'system'     => $sys,
        'messages'   => [['role' => 'user', 'content' => mb_substr($question, 0, 1000)]],
    ]);
    $ch = curl_init('https://api.anthropic.com/v1/messages');
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $payload,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 30,
        CURLOPT_HTTPHEADER     => [
            'content-type: application/json',
            'anthropic-version: 2023-06-01',
            'x-api-key: ' . $key,
        ],
    ]);
    $body = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    if ($body === false || $code !== 200) return null;
    $j = json_decode($body, true);
    if (!is_array($j) || empty($j['content']) || !is_array($j['content'])) return null;
    $text = '';
    foreach ($j['content'] as $block) {
        if (($block['type'] ?? '') === 'text') $text .= (string)($block['text'] ?? '');
    }
    $text = trim($text);
    return $text === '' ? null : $text;
}
