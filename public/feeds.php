<?php
// DuckFind Feeds — a personal RSS reader with no accounts. Your feed list is
// saved under a code (the way DuckDuckGo cloud-saves settings): the server
// stores it keyed by a salted hash of the code — no email, no password reset,
// no idea who you are. Type the same code on your iBook and your modern
// machine and both show the same feeds. Lose the code, lose the list; that is
// the whole deal, and it's why there is nothing here worth logging.
require __DIR__ . '/lib.php';
if (!df_rate('news')) df_rate_block();
header('Content-Type: text/html; charset=iso-8859-1');

define('FD_DIR',  __DIR__ . '/../data/feeds');
define('FD_MAX',  50);     // feeds per code
define('FD_SHOW', 40);     // river items shown

$act  = (string)($_POST['action'] ?? '');
$code = fd_norm((string)($_POST['code'] ?? ($_COOKIE['df_code'] ?? '')));
$err = ''; $note = ''; $created = '';

if ($act === 'signout') {
    setcookie('df_code', '', ['expires' => time() - 3600, 'path' => '/', 'samesite' => 'Lax']);
    $code = '';
} elseif ($act === 'create') {
    if (!df_rate_ok('feedcode', 10, 3600)) {
        $err = 'Too many attempts from your address - try again later.';
    } else {
        $custom = fd_norm((string)($_POST['custom'] ?? ''));
        if ($custom !== '' && strlen($custom) < 8) {
            $err = 'A custom code needs at least 8 characters (letters, digits, dashes).';
        } elseif ($custom !== '' && is_file(fd_path($custom))) {
            $err = 'That code is already in use - pick another.';
        } else {
            $code = $custom !== '' ? $custom : fd_gen();
            while ($custom === '' && is_file(fd_path($code))) $code = fd_gen();
            fd_save($code, ['created' => time(), 'feeds' => []]);
            fd_cookie($code);
            $created = $code;
        }
    }
} elseif ($act === 'code') {
    if (!df_rate_ok('feedcode', 20, 3600)) {
        $err = 'Too many attempts from your address - try again later.';
        $code = '';
    } elseif ($code === '' || !is_file(fd_path($code))) {
        $err = 'No reader found with that code.';
        $code = '';
    } else {
        fd_cookie($code);
    }
}

$data = null;
if ($code !== '' && is_file(fd_path($code))) {
    $data = json_decode((string)@file_get_contents(fd_path($code)), true);
    if (!is_array($data)) $data = null;
}

// --- signed-in mutations ------------------------------------------------------
if ($data !== null && $act === 'add') {
    $u = trim((string)($_POST['url'] ?? ''));
    if (!preg_match('#^https?://#i', $u)) $u = 'https://' . $u;
    if (count($data['feeds']) >= FD_MAX) {
        $err = 'This reader is full (' . FD_MAX . ' feeds).';
    } elseif (in_array($u, array_column($data['feeds'], 'url'), true)) {
        $err = 'That feed is already in your list.';
    } elseif (!df_feed_items($u, 3)) {
        $err = 'Could not read a feed there. Paste the RSS/Atom address itself.';
    } else {
        $data['feeds'][] = ['url' => $u, 'name' => parse_url($u, PHP_URL_HOST) ?: $u];
        fd_save($code, $data);
        $note = 'Feed added.';
    }
}
// remove: GET link, guarded by a token derived from the code so a hostile page
// can't unsubscribe you with an <img> tag
if ($data !== null && isset($_GET['rm'], $_GET['t']) && $_GET['t'] === fd_token($code)) {
    array_splice($data['feeds'], (int)$_GET['rm'], 1);
    fd_save($code, $data);
    $note = 'Feed removed.';
}

echo page_head(DUCKFIND_NAME . ' - my feeds');
echo '<form action="/" method="get"><a href="/"><b>' . DUCKFIND_NAME . '</b></a>&nbsp;&nbsp;'
   . '<input type="text" name="q" size="26">&nbsp;<input type="submit" value="Quack!"></form>';
echo '<h2>My feeds</h2>';
if ($err  !== '') echo '<p><font color="#AA0000"><b>' . e($err) . '</b></font></p>';
if ($note !== '') echo '<p><b>' . e($note) . '</b></p>';

// --- signed out: create / enter code -------------------------------------------
if ($data === null) {
    echo '<p>A personal news page for your feeds &mdash; <b>no account needed</b>. '
       . 'Your list is saved under a code; type the same code on any machine (even a '
       . 'Mac Plus) and your feeds follow you. ' . DUCKFIND_NAME . ' stores the list '
       . 'under a salted hash of the code and knows nothing about you.</p>';
    echo '<form action="/feeds.php" method="post"><input type="hidden" name="action" value="create">'
       . '<p><input type="submit" value="Create my reader"> '
       . '<font size="1">or choose your own code: '
       . '<input type="text" name="custom" size="16" maxlength="64"> (8+ characters)</font></p></form>';
    echo '<form action="/feeds.php" method="post"><input type="hidden" name="action" value="code">'
       . '<p>Already have a code? <input type="text" name="code" size="24" maxlength="64">&nbsp;'
       . '<input type="submit" value="Open my feeds"></p></form>';
    echo '<p><font size="1">Write the code down &mdash; there is no recovery (that&#39;s '
       . 'the privacy working as intended).</font></p>';
    echo page_foot(); exit;
}

if ($created !== '') {
    echo '<p><b>Your reader code:</b></p>'
       . '<p><font size="5"><tt>' . e($created) . '</tt></font></p>'
       . '<p><font size="1"><b>Write it down now.</b> It is the only key to this list '
       . '&mdash; there is no recovery. Type it on any machine to get your feeds there.</font></p><hr>';
}

// --- the river ------------------------------------------------------------------
if (!$data['feeds']) {
    echo '<p>No feeds yet. Add your first below &mdash; paste a site&#39;s RSS or Atom '
       . 'address. A few to try:</p><ul><font size="1">';
    foreach (['Hacker News' => 'https://news.ycombinator.com/rss',
              'BBC World'   => 'https://feeds.bbci.co.uk/news/world/rss.xml',
              'Ars Technica' => 'https://feeds.arstechnica.com/arstechnica/index'] as $n => $u) {
        echo '<li><tt>' . e($u) . '</tt> (' . e($n) . ')</li>';
    }
    echo '</font></ul>';
} else {
    // Fetch budget: cold feeds are real HTTP fetches (~0.5-1s each), and a
    // vintage browser shouldn't sit 30 s on a big list. Fetch fresh until the
    // budget is spent, then fall back to cached copies (up to a day old) for
    // the rest — each reload warms more of the cache, converging to fresh.
    $deadline = microtime(true) + 8.0;
    $stale = 0;
    $items = [];
    foreach ($data['feeds'] as $f) {
        if (microtime(true) < $deadline) {
            $its = df_feed_items($f['url'], 10);
        } else {
            $its = df_feed_items_stale($f['url'], 10);
            $stale++;
        }
        foreach ($its as $it) { $it['src'] = $f['name']; $items[] = $it; }
    }
    usort($items, fn($a, $b) => ($b['ts'] ?? 0) <=> ($a['ts'] ?? 0));
    $items = array_slice($items, 0, FD_SHOW);
    if ($stale > 0) {
        echo '<p><font size="1">(' . $stale . ' of ' . count($data['feeds'])
           . ' feeds shown from an earlier copy to keep this page quick &mdash; '
           . '<a href="/feeds.php">reload</a> to refresh more)</font></p>';
    }
    if (!$items) {
        echo '<p><font size="1">(no items right now - feeds may be briefly unreachable)</font></p>';
    } else {
        // headline cards: thumbnail (through the GIF proxy, honouring the
        // visitor's image settings) + title + summary — HTML 3.2 all the way
        $showImg = (($_COOKIE['df_img'] ?? '1') !== '0');
        $imMode  = in_array($_COOKIE['df_mode'] ?? 'color', ['gray', 'bw'], true)
                 ? '&amp;im=' . $_COOKIE['df_mode'] : '';
        foreach ($items as $it) {
            $ru = '/read.php?url=' . htmlspecialchars(urlencode($it['link']), ENT_QUOTES);
            echo '<p>';
            if ($showImg && ($it['img'] ?? '') !== '') {
                echo '<a href="' . $ru . '"><img src="/img.php?url='
                   . htmlspecialchars(urlencode($it['img']), ENT_QUOTES) . '&amp;w=120' . $imMode
                   . '" align="left" hspace="6" vspace="2" border="0" alt=""></a>';
            }
            echo '<a href="' . $ru . '"><b>' . e($it['title']) . '</b></a> '
               . '<font size="1" color="' . df_muted_color() . '">&ndash; ' . e($it['src'])
               . ($it['ts'] ? ', ' . gmdate('M j', $it['ts']) : '') . '</font>';
            if (($it['desc'] ?? '') !== '') echo '<br><font size="2">' . e($it['desc']) . '</font>';
            echo '</p><br clear="left">';
        }
    }
}

// --- manage ----------------------------------------------------------------------
echo '<hr><p><b>Manage feeds</b> <font size="1">(' . count($data['feeds']) . '/' . FD_MAX . ')</font></p>';
if ($data['feeds']) {
    echo '<ul><font size="1">';
    foreach ($data['feeds'] as $i => $f) {
        echo '<li>' . e($f['name']) . ' &mdash; <tt>' . e($f['url']) . '</tt> '
           . '[<a href="/feeds.php?rm=' . $i . '&amp;t=' . fd_token($code) . '">remove</a>]</li>';
    }
    echo '</font></ul>';
}
echo '<form action="/feeds.php" method="post"><input type="hidden" name="action" value="add">'
   . '<p>Add feed: <input type="text" name="url" size="34">&nbsp;'
   . '<input type="submit" value="Add"></p></form>';
echo '<p><font size="1">Your code: <tt>' . e($code) . '</tt> &mdash; type it on any other '
   . 'machine to open these feeds there.</font></p>';
echo '<form action="/feeds.php" method="post"><input type="hidden" name="action" value="signout">'
   . '<input type="submit" value="Sign out of this machine"></form>';
echo page_foot();

// --- helpers ----------------------------------------------------------------------
function fd_norm(string $c): string {
    $c = strtolower(trim($c));
    $c = preg_replace('/\s+/', '-', $c);
    return preg_match('/^[a-z0-9\-]{1,64}$/', $c) ? $c : '';
}

// The list lives under a salted hash so the files can't be matched back to
// codes. The salt is persistent (unlike the rate-limit salt) — losing it
// would orphan every reader — so it sits in the data dir, backed up with it.
function fd_salt(): string {
    static $s = null;
    if ($s !== null) return $s;
    if (!is_dir(FD_DIR)) @mkdir(FD_DIR, 0700, true);
    $f = FD_DIR . '/.salt';
    $v = @file_get_contents($f);
    if (!is_string($v) || strlen($v) < 32) {
        $v = bin2hex(random_bytes(16));
        @file_put_contents($f, $v, LOCK_EX);
        @chmod($f, 0600);
    }
    return $s = $v;
}

function fd_path(string $code): string {
    return FD_DIR . '/' . hash('sha256', fd_salt() . $code) . '.json';
}

function fd_token(string $code): string {
    return substr(hash('sha256', 'rm' . fd_salt() . $code), 0, 8);
}

function fd_save(string $code, array $data): void {
    @file_put_contents(fd_path($code), json_encode($data), LOCK_EX);
}

function fd_cookie(string $code): void {
    setcookie('df_code', $code, ['expires' => time() + 31536000, 'path' => '/', 'samesite' => 'Lax']);
    $_COOKIE['df_code'] = $code;
}

function fd_gen(): string {
    $adj = ['amber','atomic','beige','brave','bronze','busy','calm','cheery','chrome','cosmic',
            'crisp','dapper','dusty','fuzzy','gentle','golden','groovy','handy','happy','jolly',
            'lucky','mellow','mighty','neon','nifty','plucky','proud','purple','quiet','rapid',
            'retro','shiny','silver','snappy','sturdy','sunny','swift','turbo','witty','zesty'];
    $nou = ['abacus','beacon','bezel','cassette','circuit','dial','diskette','drake','duck',
            'feather','floppy','gopher','joystick','keyboard','marsh','modem','mouse','pixel',
            'plotter','pond','printer','prompt','quack','reed','resistor','ribbon','router',
            'scanner','sprite','stylus','switch','terminal','toaster','tower','trackball','tube'];
    return $adj[random_int(0, count($adj) - 1)] . '-'
         . $nou[random_int(0, count($nou) - 1)] . '-'
         . $nou[random_int(0, count($nou) - 1)] . '-'
         . random_int(10, 99);
}
