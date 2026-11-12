<?php
// DuckFind favicon proxy (added 2026-11-12): a source's site icon as a small GIF
// for the news river (df_river). Since 2026-11-12 (Derek) it is the placeholder
// in the river's picture column for headlines whose feed has no image, so the
// column is never an empty gap. s=32 (default; 16 also allowed). When a site
// has no usable icon, the placeholder is DuckFind's own duck, not a blank.
//   /fav.php?h=<host>&t=<df_fav_token(host)>[&s=16|32][&im=gray|bw]
// The token binds the host: only hosts duckfind itself put on a page get an
// icon, so this is not an open favicon proxy and can't mint cache files for
// arbitrary hosts. The visitor's browser only ever talks to duckfind; duckfind
// fetches each site's icon itself (about once a month per host) -- no third-
// party favicon service sees anything.
// Lookup: https://<host>/favicon.ico (any real image, incl. .ico), then the
// homepage's <link rel="icon"> (SVG skipped: GD can't draw it). The icon is
// flattened onto the page background (white, or dark theme's #282A36) and
// reduced to a small palette. Successes are cached 30 days, failures 1 day
// (a blank icon is served meanwhile).
require __DIR__ . '/lib.php';

$FAV_SIZE = (int)($_GET['s'] ?? 32) === 16 ? 16 : 32;
const FAV_OK_TTL = DF_FAV_OK_TTL;
const FAV_FAIL_TTL = DF_FAV_FAIL_TTL;

function fav_out(string $gif, int $secs): void {
    header('Content-Type: image/gif');
    if ($secs > 0) {
        header('Expires: ' . gmdate('D, d M Y H:i:s', time() + $secs) . ' GMT');
        header('Cache-Control: public, max-age=' . $secs);
    } else {
        header('Cache-Control: no-store');
        header('Expires: 0');
    }
    echo $gif;
    exit;
}

// a fully transparent icon-sized GIF (refusals only: not a host we linked)
function fav_blank_gif(): string {
    global $FAV_SIZE;
    $im = imagecreate($FAV_SIZE, $FAV_SIZE);
    $bg = imagecolorallocate($im, 255, 255, 255);
    imagecolortransparent($im, $bg);
    ob_start(); imagegif($im); return (string)ob_get_clean();
}

// No usable site icon: DuckFind's duck as the placeholder (local file, no fetch).
function fav_placeholder_gif(string $mode, bool $dark): string {
    // lib.php's directory is public/ however this page is loaded (tests eval it)
    $duck = @imagecreatefromgif(df_public_dir() . '/duck.gif');
    global $FAV_SIZE;
    return $duck === false ? fav_blank_gif() : df_fav_render($duck, $FAV_SIZE, $mode, $dark);
}

if (!df_rate('img')) fav_out(fav_blank_gif(), 0);

$host = strtolower(df_str($_GET['h'] ?? ''));
$tok  = df_str($_GET['t'] ?? '');
if (!preg_match('/^[a-z0-9.-]{1,253}$/', $host) || strpos($host, '.') === false
    || !hash_equals(df_fav_token($host), $tok)) {
    fav_out(fav_blank_gif(), 0);                    // not a host duckfind linked: nothing fetched
}
$mode = in_array($_GET['im'] ?? '', ['gray', 'bw'], true) ? (string)$_GET['im'] : 'color';
$dark = df_dark();
// lookup, render and 30-day / 1-day caching live in lib.php (df_fav_icon), shared
// with img.php's news-thumbnail tile
$gif = df_fav_icon($host, $FAV_SIZE, $mode, $dark);
if ($gif === null) fav_out(fav_placeholder_gif($mode, $dark), FAV_FAIL_TTL);
fav_out($gif, FAV_OK_TTL);
