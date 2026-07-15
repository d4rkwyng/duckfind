<?php
// DuckFind display settings — persist image + colour preferences in a cookie
// so they stick site-wide (e.g. a 1-bit compact Mac can default to dithered B&W).
require __DIR__ . '/lib.php';

if (isset($_GET['save'])) {
    $img   = (($_GET['images'] ?? '1') === '0') ? '0' : '1';
    $mode  = in_array($_GET['mode'] ?? '', ['gray', 'bw'], true) ? $_GET['mode'] : 'color';
    $theme = (($_GET['theme'] ?? '') === 'dark') ? 'dark' : 'light';
    $text  = (($_GET['text'] ?? '') === 'normal') ? 'normal' : 'large';
    $exp   = time() + 31536000;   // 1 year
    setcookie('df_img',   $img,   ['expires' => $exp, 'path' => '/', 'samesite' => 'Lax']);
    setcookie('df_mode',  $mode,  ['expires' => $exp, 'path' => '/', 'samesite' => 'Lax']);
    setcookie('df_theme', $theme, ['expires' => $exp, 'path' => '/', 'samesite' => 'Lax']);
    setcookie('df_text',  $text,  ['expires' => $exp, 'path' => '/', 'samesite' => 'Lax']);
    header('Location: /settings.php?saved=1', true, 302);
    exit;
}

header('Content-Type: text/html; charset=iso-8859-1');
$img   = $_COOKIE['df_img']   ?? '1';
$mode  = $_COOKIE['df_mode']  ?? 'color';
$theme = $_COOKIE['df_theme'] ?? 'light';
$text  = $_COOKIE['df_text']  ?? 'large';
$ck    = fn($cond) => $cond ? ' checked' : '';

echo page_head(DUCKFIND_NAME . ' - display settings');
echo '<form action="/" method="get"><a href="/"><b>' . DUCKFIND_NAME . '</b></a>&nbsp;&nbsp;'
   . '<input type="text" name="q" size="26">&nbsp;<input type="submit" value="Quack!"></form>';
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

echo '<p><b>Text size</b><br>';
echo '<input type="radio" name="text" value="large"'  . $ck($text !== 'normal') . '> Larger <font size="1">(easier to read on 800x600 and small screens)</font><br>';
echo '<input type="radio" name="text" value="normal"' . $ck($text === 'normal') . '> Normal</p>';

echo '<input type="submit" value="Save settings"></form>';
echo '<p><font size="1">Preferences are stored in a cookie on your machine. '
   . 'A page\'s own toolbar links can still override them per-page.</font></p>';
echo page_foot();
