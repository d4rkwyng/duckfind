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
const FAV_OK_TTL = 2592000;   // 30 days
const FAV_FAIL_TTL = 86400;   // 1 day

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

// One candidate icon URL -> GD image, or null.
function fav_load(string $url): ?GdImage {
    $r = http_get($url, 300000, '', null, 4);
    if ($r === null || (int)($r['status'] ?? 200) >= 400) return null;
    $body = (string)$r['body'];
    if ($body === '' || stripos((string)$r['ctype'], 'svg') !== false || stripos(ltrim($body), '<svg') === 0
        || stripos(ltrim($body), '<?xml') === 0) return null;
    if (strncmp($body, "\x00\x00\x01\x00", 4) === 0) return df_ico_decode($body);
    if (!preg_match('#^image/#i', (string)$r['ctype']) && strncmp($body, "\x89PNG", 4) !== 0
        && strncmp($body, 'GIF', 3) !== 0 && strncmp($body, "\xFF\xD8", 2) !== 0) return null;
    $info = @getimagesizefromstring($body);
    if ($info === false || (int)$info[0] * (int)$info[1] > 4000000) return null;
    $g = @imagecreatefromstring($body);
    return $g === false ? null : $g;
}

// The homepage's declared icons, best first (non-SVG; "icon" before apple-touch).
function fav_declared(string $host): array {
    $r = http_get('https://' . $host . '/', 60000, '', null, 4);
    if ($r === null || (int)($r['status'] ?? 200) >= 400) return [];
    $base = (string)($r['url'] ?? ('https://' . $host . '/'));
    $out = [];
    if (preg_match_all('#<link\b[^>]*>#i', (string)$r['body'], $m)) {
        foreach ($m[0] as $tag) {
            if (!preg_match('#\brel\s*=\s*["\']?([^"\'>]+)#i', $tag, $rel)) continue;
            $rels = strtolower($rel[1]);
            if (strpos($rels, 'icon') === false) continue;
            if (!preg_match('#\bhref\s*=\s*["\']([^"\']+)#i', $tag, $hr)) continue;
            $href = html_entity_decode($hr[1], ENT_QUOTES, 'UTF-8');
            if (preg_match('#\.svg(\?|$)#i', $href) || stripos($tag, 'image/svg') !== false) continue;
            $abs = absolutize($base, $href);
            if (!preg_match('#^https?://#i', $abs)) continue;
            $out[] = [strpos($rels, 'apple') !== false ? 1 : 0, $abs];
        }
    }
    usort($out, fn($a, $b) => $a[0] <=> $b[0]);
    return array_values(array_unique(array_column($out, 1)));
}

// Icon (any size) -> a FAV_SIZE GIF on the page background, in the visitor's mode.
function fav_render(GdImage $src, string $mode, bool $dark): string {
    global $FAV_SIZE;
    $out = imagecreatetruecolor($FAV_SIZE, $FAV_SIZE);
    imagefill($out, 0, 0, $dark ? imagecolorallocate($out, 0x28, 0x2A, 0x36) : imagecolorallocate($out, 255, 255, 255));
    imagealphablending($out, true);
    imagecopyresampled($out, $src, 0, 0, 0, 0, $FAV_SIZE, $FAV_SIZE, imagesx($src), imagesy($src));
    if ($mode !== 'color') imagefilter($out, IMG_FILTER_GRAYSCALE);
    if ($mode === 'bw') imagetruecolortopalette($out, true, 2);
    else imagetruecolortopalette($out, false, 32);
    ob_start(); imagegif($out); $gif = (string)ob_get_clean();
    return $gif;
}
// No usable site icon: DuckFind's duck as the placeholder (local file, no fetch).
function fav_placeholder_gif(string $mode, bool $dark): string {
    // lib.php's directory is public/ however this page is loaded (tests eval it)
    $duck = @imagecreatefromgif(df_public_dir() . '/duck.gif');
    return $duck === false ? fav_blank_gif() : fav_render($duck, $mode, $dark);
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
$ckey = 'fav:' . $FAV_SIZE . ':' . $mode . ':' . ($dark ? 'd' : 'l') . ':' . $host;
if (($hit = df_cache_get($ckey, FAV_OK_TTL)) !== null) fav_out($hit, FAV_OK_TTL);
if (df_cache_get('favfail:' . $host, FAV_FAIL_TTL) !== null) fav_out(fav_placeholder_gif($mode, $dark), FAV_FAIL_TTL);

$src = fav_load('https://' . $host . '/favicon.ico');
if ($src === null) {
    foreach (array_slice(fav_declared($host), 0, 3) as $u) {
        if (($src = fav_load($u)) !== null) break;
    }
}
if ($src === null) {
    df_cache_put('favfail:' . $host, '1');
    df_daily_inc('favfail');
    fav_out(fav_placeholder_gif($mode, $dark), FAV_FAIL_TTL);
}

$gif = fav_render($src, $mode, $dark);
unset($src);
df_cache_put($ckey, $gif);
df_daily_inc('favok');
fav_out($gif, FAV_OK_TTL);
