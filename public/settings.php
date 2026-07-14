<?php
// DuckFind display settings — persist image + colour preferences in a cookie
// so they stick site-wide (e.g. a 1-bit compact Mac can default to dithered B&W).
require __DIR__ . '/lib.php';

if (isset($_GET['save'])) {
    $img   = (($_GET['images'] ?? '1') === '0') ? '0' : '1';
    $mode  = in_array($_GET['mode'] ?? '', ['gray', 'bw'], true) ? $_GET['mode'] : 'color';
    $theme = (($_GET['theme'] ?? '') === 'dark') ? 'dark' : 'light';
    $exp   = time() + 31536000;   // 1 year
    setcookie('df_img',   $img,   ['expires' => $exp, 'path' => '/', 'samesite' => 'Lax']);
    setcookie('df_mode',  $mode,  ['expires' => $exp, 'path' => '/', 'samesite' => 'Lax']);
    setcookie('df_theme', $theme, ['expires' => $exp, 'path' => '/', 'samesite' => 'Lax']);
    header('Location: /settings.php?saved=1', true, 302);
    exit;
}

header('Content-Type: text/html; charset=iso-8859-1');
$img   = $_COOKIE['df_img']   ?? '1';
$mode  = $_COOKIE['df_mode']  ?? 'color';
$theme = $_COOKIE['df_theme'] ?? 'light';
$ck    = fn($cond) => $cond ? ' checked' : '';

echo page_head(DUCKFIND_NAME . ' - display settings');
echo '<form action="/" method="get"><a href="/"><b>' . DUCKFIND_NAME . '</b></a>&nbsp;&nbsp;'
   . '<input type="text" name="q" size="26">&nbsp;<input type="submit" value="Search"></form>';
echo '<h2>Display settings</h2>';
if (isset($_GET['saved'])) echo '<p><b>Saved.</b> These apply to every page you read.</p>';

echo '<form action="/settings.php" method="get">';
echo '<input type="hidden" name="save" value="1">';

echo '<p><b>Images</b><br>';
echo '<input type="radio" name="images" value="1"' . $ck($img !== '0') . '> Show images (converted to GIF)<br>';
echo '<input type="radio" name="images" value="0"' . $ck($img === '0') . '> Text only (fastest)</p>';

echo '<p><b>Colour</b> <font size="1">(for images)</font><br>';
echo '<input type="radio" name="mode" value="color"' . $ck($mode === 'color') . '> Colour<br>';
echo '<input type="radio" name="mode" value="gray"'  . $ck($mode === 'gray')  . '> Grayscale<br>';
echo '<input type="radio" name="mode" value="bw"'    . $ck($mode === 'bw')    . '> Black &amp; white, dithered <font size="1">(1-bit displays)</font></p>';

echo '<p><b>Theme</b><br>';
echo '<input type="radio" name="theme" value="light"' . $ck($theme !== 'dark') . '> Light <font size="1">(black on white)</font><br>';
echo '<input type="radio" name="theme" value="dark"'  . $ck($theme === 'dark') . '> Dark <font size="1">(light on dark)</font></p>';

echo '<input type="submit" value="Save settings"></form>';
echo '<p><font size="1">Preferences are stored in a cookie on your machine. '
   . 'A page\'s own toolbar links can still override them per-page.</font></p>';

echo '<h2>Privacy</h2>';
echo '<p><font size="1">DuckFind keeps no logs of what you search or read. '
   . 'Searches and pages are fetched by the server on your behalf, so websites and '
   . 'search engines see DuckFind&#39;s address, not yours. Fetched pages and images '
   . 'live briefly in a server cache keyed by URL &mdash; never by visitor &mdash; and '
   . 'expire within days. Rate limiting stores a salted hash of your address, never '
   . 'the address itself.'
   . (trim((string)df_cfg('ai_api_key', '')) !== ''
       ? ' The optional <tt>!ai</tt> shortcut sends that question &mdash; and nothing '
       . 'else &mdash; to Anthropic to generate the answer.'
       : '')
   . '</font></p>';
echo page_foot();
