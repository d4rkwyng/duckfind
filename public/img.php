<?php
// DuckFind image proxy: fetch a modern image (JPEG/PNG/WebP/AVIF...), downscale
// to vintage-friendly dimensions, optionally reduce colour (grayscale or dithered
// black & white), and serve as GIF -- the one format every old browser renders.
require __DIR__ . '/lib.php';

define('IMG_MAX_H', (int)df_cfg('img_max_h', 600));

// blank gif rather than an HTML 429 (not a source failure). no-store: a blank
// the browser kept for 15 min would outlast the 60 s window and leave this
// image missing on every reload long after the visitor stopped tripping it.
if (!df_rate('img')) { img_blank(0); }

$url  = df_input('url');
$mode = df_img_mode($_GET['im'] ?? 'color');   // 'ascii' is a page mode, never a GIF one: -> color
$defW = (int)df_cfg('img_max_w', 480);
$w    = (int)($_GET['w'] ?? $defW);
// Snap to a small preset set: the cache key includes $w, so allowing all 721
// integers 80-800 would let one image mint hundreds of cache files via ?w=N.
if ($w < 80 || $w > 800) { $w = $defW; }
else { $presets = [88, 160, 240, 320, 480, 600, 800];
       usort($presets, fn($a, $b) => abs($a - $w) <=> abs($b - $w)); $w = $presets[0]; }
$year = preg_replace('/\D/', '', df_str($_GET['year'] ?? ''));
// c=1 (news thumbnails): centre-crop to a fixed 4:3 box, $w wide, so every row
// lines up whatever the source's shape (Derek 2026-11-12)
$crop = ($_GET['c'] ?? '') === '1';

// not a fetchable URL: blank, but no negative-cache write (nothing was fetched,
// and junk input would otherwise mint a cache file per distinct value)
if (!preg_match('#^https?://#i', $url)) { img_blank(); }

// serve from cache if we've already converted this exact url+mode+width+era
// img2: transparent images are composited onto the page background since
// 2026-11-12 (was black), so the theme is part of the key and old entries retire.
$bgDark = df_dark();
$ckey = "img2:$mode:$w" . ($crop ? 'c' : '') . ':' . ($bgDark ? 'd' : 'l') . ":$year:$url";
if (($hit = df_cache_get($ckey, 604800)) !== null) {   // 7-day image cache
    header('Content-Type: image/gif');
    img_cache_headers();
    echo $hit; exit;
}
// short negative cache: a dead/blocked source served a blank recently — skip the
// refetch (a transient failure clears in 15 min; a real dead image stays blank
// but never re-hammers the origin per viewer)
// Keyed by era too: a throttled Wayback fetch must not blank the live image
// (or another year's copy) of the same URL, and vice versa.
if (df_cache_get(df_imgfail_key($url, $year), 900) !== null) { img_blank(); }

// From here on this does a real fetch and a GD decode -- gate it (see
// lib.php). A real browser's <img> tag already carries the cookie set by the
// page that embedded it, so this round-trips invisibly (same as pdf.php's
// gif=1 sub-request). Cache hits above stay ungated.
df_require_browser_proof();

// Shared fetch -> validate -> decode (lib.php df_img_load): the SSRF-checked
// fetch (or Wayback's era-correct copy), the img_fetch_cap byte cap, the
// image/* type check and the 12 MP decompression-bomb guard. Failures are
// negative-cached there.
$src = df_img_load($url, $year);
if ($src === null) { img_fail(); }

$sw = imagesx($src); $sh = imagesy($src);
if ($crop) {
    // largest 4:3 rectangle in the middle of the source, resampled to $w x 3/4 $w
    $tw = $w; $th = (int)round($w * 3 / 4);
    [$cx, $cy, $cw, $ch] = df_crop_43($sw, $sh);
    $img = imagecreatetruecolor($tw, $th);
    imagealphablending($img, false); imagesavealpha($img, true);
    imagefill($img, 0, 0, imagecolorallocatealpha($img, 0, 0, 0, 127));
    imagecopyresampled($img, $src, 0, 0, $cx, $cy, $tw, $th, $cw, $ch);
    unset($src);
    $scale = 1; $src = $img;
}
$scale = min(1, $w / max(1, $sw), IMG_MAX_H / max(1, $sh));
if ($crop) $scale = 1;
if ($scale < 1) {
    // bilinear is visually indistinguishable from bicubic at these output sizes
    // and much cheaper on the single vCPU
    $img = imagescale($src, (int)round($sw * $scale), (int)round($sh * $scale), IMG_BILINEAR_FIXED);
    unset($src);
    if ($img === false) { img_fail(); }
} else {
    $img = $src;
}

// Flatten any transparency onto the page background before palette
// conversion: GIF output here carries no alpha, so a transparent PNG (logos,
// diagrams, formula images) came out on solid black (2026-11-12). Done after
// the downscale (imagescale keeps alpha) so a large image isn't copied twice.
$img = img_flatten($img, $bgDark ? [0x28, 0x2A, 0x36] : [255, 255, 255]);

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
    // which matters on dial-up. 256, not 255, on the larger-image side: GIF's
    // real palette limit, free (same LZW code size either way).
    if (imageistruecolor($img)) imagetruecolortopalette($img, true, $w <= 160 ? 64 : 256);
}

ob_start();
imagegif($img);
$gif = ob_get_clean();
unset($img);

df_cache_put($ckey, $gif);
header('Content-Type: image/gif');
img_cache_headers();
echo $gif;
exit;

// Copy $im onto an opaque canvas of colour $rgb. Truecolor sources with an
// alpha channel and palette sources with a transparent index both end up
// composited; fully opaque images come out unchanged.
function img_flatten(GdImage $im, array $rgb): GdImage {
    $w = imagesx($im); $h = imagesy($im);
    $out = imagecreatetruecolor($w, $h);
    imagefill($out, 0, 0, imagecolorallocate($out, $rgb[0], $rgb[1], $rgb[2]));
    imagealphablending($out, true);
    imagecopy($out, $im, 0, 0, 0, 0, $w, $h);
    return $out;
}

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
    global $url, $year;
    if (!empty($url)) df_cache_put(df_imgfail_key($url, (string)($year ?? '')), '1');
    img_blank();
}

// 1x1 transparent GIF so broken refs degrade invisibly on old browsers.
// $secs = 0 for a transient refusal (rate limit) that must not be cached.
function img_blank(int $secs = 900): void {
    // ph=<source name> (news thumbnails): a grey tile with the source's name
    // instead of an invisible pixel, so a story whose picture failed still
    // has a placeholder (Derek 2026-11-12)
    if (isset($_GET['ph']) && ($ph = img_placeholder(df_ph_label(df_str($_GET['ph'])), $secs > 0 ? img_tile_icon() : null)) !== null) {
        header('Content-Type: image/gif');
        if ($secs > 0) img_cache_headers($secs);
        else { header('Cache-Control: no-store'); header('Expires: 0'); }
        echo $ph;
        exit;
    }
    $im = imagecreate(1, 1);
    $bg = imagecolorallocate($im, 255, 255, 255);
    imagecolortransparent($im, $bg);
    header('Content-Type: image/gif');
    if ($secs > 0) {
        img_cache_headers($secs);
    } else {
        header('Cache-Control: no-store');
        header('Expires: 0');                // HTTP/1.0 browsers ignore Cache-Control
    }
    imagegif($im);
    unset($im);
    exit;
}

// The source site's icon for the tile (fh=<host>&ft=<df_fav_token>), as a 32px
// GIF, or null. Only hosts duckfind linked (token-bound, like fav.php); the icon
// is fetched at most once a day per host and cached 30 days (df_fav_icon).
function img_tile_icon(): ?string {
    $host = strtolower(df_str($_GET['fh'] ?? ''));
    if (!preg_match('/^[a-z0-9.-]{1,253}$/', $host) || strpos($host, '.') === false
        || !hash_equals(df_fav_token($host), df_str($_GET['ft'] ?? ''))) return null;
    return df_fav_icon($host, 32, df_img_mode($_GET['im'] ?? 'color'), df_dark());
}

// An 88x66 tile: the site's icon (when there is one) above its name, else the
// name alone, centred in GD's built-in font and wrapped on spaces. Light grey on
// light pages, dark grey on dark ones.
function img_placeholder(string $label, ?string $icon = null): ?string {
    $tw = 88; $th = 66;
    $ic = $icon !== null ? @imagecreatefromstring($icon) : false;
    $im = $ic !== false ? imagecreatetruecolor($tw, $th) : imagecreate($tw, $th);
    $dark = df_dark();
    $bw = df_img_mode($_GET['im'] ?? 'color') === 'bw';
    $bg = $bw ? imagecolorallocate($im, 255, 255, 255) : ($dark ? imagecolorallocate($im, 51, 51, 51) : imagecolorallocate($im, 221, 221, 221));
    $fg = $bw ? imagecolorallocate($im, 0, 0, 0) : ($dark ? imagecolorallocate($im, 204, 204, 204) : imagecolorallocate($im, 85, 85, 85));
    imagefill($im, 0, 0, $bg);   // truecolor canvas (icon tile) has no implicit background
    if ($bw) imagerectangle($im, 0, 0, $tw - 1, $th - 1, $fg);
    // font 3 unless a word won't fit, then font 2 (always 2 under an icon)
    $font = $ic === false && df_tile_fits($label, intdiv($tw - 6, imagefontwidth(3))) ? 3 : 2;
    $cw = imagefontwidth($font); $ch = imagefontheight($font);
    $lines = df_tile_lines($label, intdiv($tw - 6, $cw));
    $lines = array_slice($lines, 0, $ic !== false ? 2 : 3);
    $y = intdiv($th - count($lines) * $ch, 2);
    if ($ic !== false) {   // 32px icon at the top, the name under it
        imagecopy($im, $ic, intdiv($tw - 32, 2), 5, 0, 0, min(32, imagesx($ic)), min(32, imagesy($ic)));
        $y = 41;
    }
    foreach ($lines as $ln) {
        imagestring($im, $font, intdiv($tw - strlen($ln) * $cw, 2), $y, $ln, $fg);
        $y += $ch;
    }
    if ($ic !== false) imagetruecolortopalette($im, false, 64);
    ob_start(); imagegif($im); return (string)ob_get_clean();
}
