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
    img_cache_headers();
    echo $hit; exit;
}
// short negative cache: a dead/blocked source served a blank recently — skip the
// refetch (a transient failure clears in 15 min; a real dead image stays blank
// but never re-hammers the origin per viewer)
if (df_cache_get("imgfail:$url", 900) !== null) { img_blank(); }

// in Wayback mode, fetch the era-correct archived image (trying both HTTP/HTTPS)
if ($year !== '') {
    $ts = strlen($year) === 4 ? $year . '0601' : $year;
    $ts = substr(str_pad($ts, 14, '0'), 0, 14);
    $res = df_wayback_get($ts, $url, 604800, IMG_FETCH);
} else {
    $res = http_get($url, IMG_FETCH);
}
if ($res === null || !preg_match('#^image/#i', $res['ctype'])) { img_fail(); }

// Decompression-bomb guard: read dimensions from the header BEFORE decoding the
// full bitmap. A tiny compressed file can declare enormous dimensions; GD would
// allocate width*height*4 bytes in imagecreatefromstring and OOM the server. If
// we can't size-check it (getimagesize can't parse it, e.g. AVIF), refuse. The
// 12 MP cap keeps peak GD memory (~w*h*4 ≈ 48 MB) under PHP's 128 MB default
// even with a few concurrent decodes on the 1 GB box; output is capped at
// 800x600, so nothing visible is lost.
$info = @getimagesizefromstring($res['body']);
if ($info === false || (int)$info[0] * (int)$info[1] > 12000000) { img_fail(); }

$src = @imagecreatefromstring($res['body']);
if ($src === false) { img_fail(); }

$sw = imagesx($src); $sh = imagesy($src);
$scale = min(1, $w / max(1, $sw), IMG_MAX_H / max(1, $sh));
if ($scale < 1) {
    // bilinear is visually indistinguishable from bicubic at these output sizes
    // and much cheaper on the single vCPU
    $img = imagescale($src, (int)round($sw * $scale), (int)round($sh * $scale), IMG_BILINEAR_FIXED);
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
    // small images (feed thumbnails etc.) don't need a full palette — 64
    // colours is visually identical at that size and ~30% fewer bytes,
    // which matters on dial-up
    if (imageistruecolor($img)) imagetruecolortopalette($img, true, $w <= 160 ? 64 : 255);
}

ob_start();
imagegif($img);
$gif = ob_get_clean();
imagedestroy($img);

df_cache_put($ckey, $gif);
header('Content-Type: image/gif');
img_cache_headers();
echo $gif;
exit;

// Both Cache-Control (HTTP/1.1) and Expires (HTTP/1.0-era browsers, which
// ignore Cache-Control) — so vintage clients actually cache images instead of
// refetching one per pageview.
function img_cache_headers(int $secs = 86400): void {
    header('Expires: ' . gmdate('D, d M Y H:i:s', time() + $secs) . ' GMT');
    header('Cache-Control: public, max-age=' . $secs);
}

// A fetch/decode failure: negative-cache this source URL ~15 min so a popular
// cached article doesn't refetch a dead image (up to 8 MB, 12 s) per viewer,
// then serve the blank.
function img_fail(): void {
    global $url;
    if (!empty($url)) df_cache_put("imgfail:$url", '1');
    img_blank();
}

// 1x1 transparent GIF so broken refs degrade invisibly on old browsers.
function img_blank(): void {
    $im = imagecreate(1, 1);
    $bg = imagecolorallocate($im, 255, 255, 255);
    imagecolortransparent($im, $bg);
    header('Content-Type: image/gif');
    img_cache_headers(900);
    imagegif($im);
    imagedestroy($im);
    exit;
}
