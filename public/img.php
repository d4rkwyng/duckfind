<?php
// DuckFind image proxy: fetch a modern image (JPEG/PNG/WebP/AVIF...), downscale
// to vintage-friendly dimensions, optionally reduce colour (grayscale or dithered
// black & white), and serve as GIF -- the one format every old browser renders.
require __DIR__ . '/lib.php';

define('IMG_MAX_H', (int)df_cfg('img_max_h', 600));
define('IMG_FETCH', (int)df_cfg('img_fetch_cap', 8000000));   // source byte cap

if (!df_rate('img')) { img_fail(); }   // blank gif rather than an HTML 429

$url  = df_input('url');
$mode = strtolower($_GET['im'] ?? 'color');
if (!in_array($mode, ['color', 'gray', 'bw'], true)) $mode = 'color';
$defW = (int)df_cfg('img_max_w', 480);
$w    = (int)($_GET['w'] ?? $defW);
if ($w < 80 || $w > 800) $w = $defW;                // sane width presets only
$year = preg_replace('/\D/', '', (string)($_GET['year'] ?? ''));

if (!preg_match('#^https?://#i', $url)) { img_fail(); }

// serve from cache if we've already converted this exact url+mode+width+era
$ckey = "img:$mode:$w:$year:$url";
if (($hit = df_cache_get($ckey, 604800)) !== null) {   // 7-day image cache
    header('Content-Type: image/gif');
    header('Cache-Control: public, max-age=86400');
    echo $hit; exit;
}

// in Wayback mode, fetch the era-correct archived image, not today's (dead) one
$fetchUrl = $url;
if ($year !== '') {
    $ts = strlen($year) === 4 ? $year . '0601' : $year;
    $ts = substr(str_pad($ts, 14, '0'), 0, 14);
    $fetchUrl = 'http://web.archive.org/web/' . $ts . 'id_/' . $url;   // HTTPS is throttled under load
}

$res = http_get($fetchUrl, IMG_FETCH);
if ($res === null || !preg_match('#^image/#i', $res['ctype'])) { img_fail(); }

// Decompression-bomb guard: read dimensions from the header BEFORE decoding the
// full bitmap. A tiny compressed file can declare enormous dimensions; GD would
// allocate width*height*4 bytes in imagecreatefromstring and OOM the server.
// If we can't size-check it (getimagesize can't parse it, e.g. AVIF), refuse —
// don't hand an un-measured bitmap to GD.
$info = @getimagesizefromstring($res['body']);
if ($info === false || (int)$info[0] * (int)$info[1] > 30000000) { img_fail(); }  // >30 MP = refuse

$src = @imagecreatefromstring($res['body']);
if ($src === false) { img_fail(); }

$sw = imagesx($src); $sh = imagesy($src);
$scale = min(1, $w / max(1, $sw), IMG_MAX_H / max(1, $sh));
if ($scale < 1) {
    $img = imagescale($src, (int)round($sw * $scale), (int)round($sh * $scale), IMG_BICUBIC);
    imagedestroy($src);
    if ($img === false) { img_fail(); }
} else {
    $img = $src;
}

if ($mode === 'gray') {
    imagefilter($img, IMG_FILTER_GRAYSCALE);
    if (imageistruecolor($img)) imagetruecolortopalette($img, false, 64);   // 64-gray palette
} elseif ($mode === 'bw') {
    imagefilter($img, IMG_FILTER_GRAYSCALE);
    imagefilter($img, IMG_FILTER_CONTRAST, -12);        // lift midtones so dithering reads well
    imagetruecolortopalette($img, true, 2);             // dither=true, 2 colours = Floyd-Steinberg B&W
} else {
    if (imageistruecolor($img)) imagetruecolortopalette($img, true, 255);
}

ob_start();
imagegif($img);
$gif = ob_get_clean();
imagedestroy($img);

df_cache_put($ckey, $gif);
header('Content-Type: image/gif');
header('Cache-Control: public, max-age=86400');
echo $gif;
exit;

function img_fail(): void {
    // 1x1 transparent GIF so broken refs degrade invisibly on old browsers
    header('Content-Type: image/gif');
    header('Cache-Control: public, max-age=3600');
    $im = imagecreate(1, 1);
    $bg = imagecolorallocate($im, 255, 255, 255);
    imagecolortransparent($im, $bg);
    imagegif($im);
    imagedestroy($im);
    exit;
}
