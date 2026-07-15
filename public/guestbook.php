<?php
// DuckFind guestbook — because it isn't the old web without one. Flat-file
// JSONL storage in ../data (outside the web root's reach for parsing, inside
// the repo dir but git-ignored). New entries land in a pending queue and only
// appear after the operator approves them with tools/guestbook.php — no web
// admin, no auth surface, no spam wall.
require __DIR__ . '/lib.php';

define('GB_PENDING',  __DIR__ . '/../data/guestbook-pending.jsonl');
define('GB_APPROVED', __DIR__ . '/../data/guestbook-approved.jsonl');
define('GB_SHOW', 50);            // newest entries shown
define('GB_QUEUE_CAP', 500000);   // pending bytes before we stop taking posts

header('Content-Type: text/html; charset=iso-8859-1');

$posted = false;
$error  = '';
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    // the hidden "website" field is a honeypot: humans leave it empty, form
    // bots fill every field — those posts are silently accepted and dropped
    $trap = trim((string)($_POST['website'] ?? ''));
    $name = trim(preg_replace('/[\x00-\x1F\x7F]/', '', (string)($_POST['name'] ?? '')));
    $msg  = trim(preg_replace('/[\x00-\x08\x0B-\x1F\x7F]/', '', (string)($_POST['msg'] ?? '')));
    $name = mb_substr($name, 0, 40);
    $msg  = mb_substr($msg, 0, 500);
    if ($name === '' || $msg === '') {
        $error = 'Please fill in both a name and a message.';
    } elseif (!df_rate_ok('guestbook', 3, 3600)) {
        $error = 'Too many entries from your address just now - try again later.';
    } elseif (is_file(GB_PENDING) && filesize(GB_PENDING) > GB_QUEUE_CAP) {
        $error = 'The guestbook queue is full at the moment - please try again tomorrow.';
    } elseif ($trap === '') {
        @file_put_contents(GB_PENDING,
            json_encode(['t' => time(), 'name' => $name, 'msg' => $msg]) . "\n",
            FILE_APPEND | LOCK_EX);
        $posted = true;
    } else {
        $posted = true;   // honeypot hit: pretend success, store nothing
    }
}

echo page_head(DUCKFIND_NAME . ' - guestbook');
echo '<form action="/" method="get"><a href="/"><b>' . DUCKFIND_NAME . '</b></a>&nbsp;&nbsp;'
   . '<input type="text" name="q" size="26">&nbsp;<input type="submit" value="Quack!"></form>';
echo '<h2>Guestbook</h2>';
echo '<p><font size="1">Sign in from your vintage machine! Say what hardware and browser '
   . 'got you here. Entries appear after a quick review.</font></p>';

if ($posted) {
    echo '<p><b>Thanks for signing!</b> Your entry will appear once it has been reviewed.</p>';
} else {
    if ($error !== '') echo '<p><font color="#AA0000"><b>' . e($error) . '</b></font></p>';
    echo '<form action="/guestbook.php" method="post">';
    echo '<p>Name: <input type="text" name="name" size="24" maxlength="40"><br>';
    // honeypot: hidden from humans via HTML 3.2-safe trick (no CSS) — a tiny
    // field with an instruction old and new browsers alike will render but
    // humans are told to skip; bots fill it anyway
    echo '<font size="1">Leave this box empty: <input type="text" name="website" size="2"></font><br>';
    echo 'Message:<br><textarea name="msg" rows="4" cols="40"></textarea><br>';
    echo '<input type="submit" value="Sign the guestbook"></p></form>';
}

echo '<hr>';
$lines = is_file(GB_APPROVED) ? file(GB_APPROVED, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
if (!$lines) {
    echo '<p><i>No entries yet - be the first!</i></p>';
} else {
    foreach (array_reverse(array_slice($lines, -GB_SHOW)) as $line) {
        $en = json_decode($line, true);
        if (!is_array($en)) continue;
        echo '<p><b>' . e((string)($en['name'] ?? '?')) . '</b> '
           . '<font size="1" color="' . df_muted_color() . '">'
           . gmdate('Y-m-d', (int)($en['t'] ?? 0)) . '</font><br>'
           . nl2br(e((string)($en['msg'] ?? ''))) . '</p>';
    }
}
echo page_foot();
