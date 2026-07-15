<?php
// Guestbook moderation CLI. Run on the server as any user who can write data/:
//   php tools/guestbook.php list
//   php tools/guestbook.php approve 2      # move pending entry #2 live
//   php tools/guestbook.php reject 2       # drop pending entry #2
//   php tools/guestbook.php approve all
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }

$pending  = __DIR__ . '/../data/guestbook-pending.jsonl';
$approved = __DIR__ . '/../data/guestbook-approved.jsonl';

$cmd = $argv[1] ?? 'list';
$arg = $argv[2] ?? '';
$rows = is_file($pending) ? file($pending, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];

if ($cmd === 'list') {
    if (!$rows) { echo "No pending entries.\n"; exit; }
    foreach ($rows as $i => $line) {
        $e = json_decode($line, true) ?: [];
        printf("#%d  %s  %s\n    %s\n", $i + 1,
            gmdate('Y-m-d H:i', (int)($e['t'] ?? 0)),
            (string)($e['name'] ?? '?'),
            str_replace("\n", "\n    ", (string)($e['msg'] ?? '')));
    }
    exit;
}

if ($cmd !== 'approve' && $cmd !== 'reject') {
    fwrite(STDERR, "usage: guestbook.php list | approve <n|all> | reject <n|all>\n");
    exit(1);
}
if (!$rows) { echo "No pending entries.\n"; exit; }

$idx = [];
if ($arg === 'all') {
    $idx = range(0, count($rows) - 1);
} elseif (ctype_digit($arg) && (int)$arg >= 1 && (int)$arg <= count($rows)) {
    $idx = [(int)$arg - 1];
} else {
    fwrite(STDERR, "no such entry: $arg (see 'list')\n");
    exit(1);
}

$keep = [];
foreach ($rows as $i => $line) {
    if (in_array($i, $idx, true)) {
        if ($cmd === 'approve') file_put_contents($approved, $line . "\n", FILE_APPEND | LOCK_EX);
        echo ($cmd === 'approve' ? "approved" : "rejected") . " #" . ($i + 1) . "\n";
    } else {
        $keep[] = $line;
    }
}
file_put_contents($pending, $keep ? implode("\n", $keep) . "\n" : '', LOCK_EX);
