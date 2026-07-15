<?php
// DuckFind maps — static street maps and text directions for vintage browsers.
// OpenStreetMap tiles are stitched server-side and served as one GIF (the same
// colour/gray/1-bit modes as img.php); panning and zooming are plain links, so
// it works on anything that can show an image. Directions come from the public
// OSRM demo server as a numbered list. Geocoding reuses Open-Meteo (same as
// weather.php): city/town/landmark names, not street addresses.
//
// Upstream etiquette: OSM's tile policy requires an honest identifying
// user-agent (no browser UAs) and caching — tiles are cached 7 days, composed
// maps 7 days, and the zoom range is capped. Same UA is sent to OSRM.
require __DIR__ . '/lib.php';

define('MAP_W', 480);
define('MAP_H', 320);
define('MAP_ZMIN', 2);
define('MAP_ZMAX', 16);
define('MAP_UA', 'DuckFind/1.0 (+' . df_cfg('base_url', 'http://duckfind.com') . ')');

// MapQuest-'96-style click-to-recentre: the map <img> carries ismap inside
// <a href="/map.php/c/lat/lon/z/mode">, so any browser back to Mosaic appends
// "?x,y" of the click; we convert that pixel to the new centre and redirect.
// (Must run after the define()s above — they execute in order at runtime.)
if (preg_match('#/c/(-?[\d.]+)/(-?[\d.]+)/(\d+)/([a-z]+)$#', $_SERVER['PATH_INFO'] ?? '', $cm)) {
    [, $clat, $clon, $cz, $cim] = $cm;
    [$clat, $clon, $cz] = map_clamp((float)$clat, (float)$clon, (int)$cz);
    if (preg_match('/^(\d+),(\d+)$/', $_SERVER['QUERY_STRING'] ?? '', $xy)) {
        [$px, $py] = map_px($clat, $clon, $cz);
        [$clat, $clon] = map_lonlat($px - MAP_W / 2 + min((int)$xy[1], MAP_W),
                                    $py - MAP_H / 2 + min((int)$xy[2], MAP_H), $cz);
    }
    header('Location: /map.php?lat=' . round($clat, 5) . '&lon=' . round($clon, 5)
         . '&z=' . $cz . '&im=' . $cim, true, 302);
    exit;
}

// --- slippy-map math -------------------------------------------------------
// Global pixel coordinates at zoom $z (256px tiles, Web Mercator).
function map_px(float $lat, float $lon, int $z): array {
    $n = 256 * (2 ** $z);
    $x = ($lon + 180) / 360 * $n;
    $y = (1 - log(tan(deg2rad($lat)) + 1 / cos(deg2rad($lat))) / M_PI) / 2 * $n;
    return [$x, $y];
}
function map_lonlat(float $px, float $py, int $z): array {
    $n = 256 * (2 ** $z);
    $lon = $px / $n * 360 - 180;
    $lat = rad2deg(atan(sinh(M_PI * (1 - 2 * $py / $n))));
    return [$lat, $lon];
}
function map_clamp(float $lat, float $lon, int $z): array {
    $lat = max(-85.0, min(85.0, $lat));
    $lon = fmod($lon + 540, 360) - 180;                 // wrap to [-180,180)
    $z   = max(MAP_ZMIN, min(MAP_ZMAX, $z));
    return [$lat, $lon, $z];
}

// --- geocoding ---------------------------------------------------------------
// Nominatim first (landmarks, street addresses, "city state" all work), with
// Open-Meteo's city gazetteer as fallback if Nominatim is down. Nominatim's
// usage policy — max 1 req/s, identifying UA, cache results — is honoured via
// map_nominatim_pace(), MAP_UA, and a 7-day result cache (misses cached too,
// so repeated bad queries don't hammer it).
function map_geocode(string $place, ?array $near = null): ?array {
    // $near biases ambiguous names toward a reference point (Nominatim viewbox
    // preference, not bounded) — "apple park" from Cupertino should mean the
    // one in Cupertino, not the one in South Africa.
    $bias = $near ? '&viewbox=' . round($near['lon'] - 2, 2) . ',' . round($near['lat'] + 2, 2)
                  . ',' . round($near['lon'] + 2, 2) . ',' . round($near['lat'] - 2, 2) : '';
    $key = 'geo:' . mb_strtolower(trim($place))
         . ($near ? ':' . round($near['lat']) . ',' . round($near['lon']) : '');
    if (($c = df_cache_get($key, 604800)) !== null) {
        $d = @unserialize($c);
        if (is_array($d)) return $d ?: null;
    }
    $res = null;
    map_nominatim_pace();
    $g = http_get('https://nominatim.openstreetmap.org/search?format=jsonv2&limit=1'
        . '&accept-language=en' . $bias . '&q=' . urlencode($place), 3000000, MAP_UA);
    $j = $g ? json_decode($g['body'], true) : null;
    if (!empty($j[0]['lat'])) {
        $parts = array_map('trim', explode(',', (string)($j[0]['display_name'] ?? $place)));
        $res = ['lat' => (float)$j[0]['lat'], 'lon' => (float)$j[0]['lon'],
                'name' => implode(', ', array_slice($parts, 0, 3)),
                'zoom' => map_bbox_zoom($j[0]['boundingbox'] ?? null)];
    } elseif ($g === null) {
        $g2 = http_get_cached('https://geocoding-api.open-meteo.com/v1/search?count=1&language=en&name='
            . urlencode($place), 604800);
        $j2 = $g2 ? json_decode($g2['body'], true) : null;
        if (!empty($j2['results'][0]['latitude'])) {
            $r = $j2['results'][0];
            $res = ['lat' => (float)$r['latitude'], 'lon' => (float)$r['longitude'],
                    'name' => $r['name']
                            . (!empty($r['admin1']) ? ', ' . $r['admin1'] : '')
                            . (!empty($r['country']) ? ', ' . $r['country'] : ''),
                    'zoom' => 12];
        }
    }
    df_cache_put($key, serialize($res ?: []));
    return $res;
}

// Zoom that roughly fits the result's bounding box in the viewport: a country
// arrives zoomed out, a landmark zoomed in.
function map_bbox_zoom(?array $bb): int {
    if (!$bb || count($bb) < 4) return 12;
    $span = max(abs((float)$bb[1] - (float)$bb[0]), abs((float)$bb[3] - (float)$bb[2]), 0.0004);
    return max(MAP_ZMIN, min(MAP_ZMAX, (int)floor(log(360 / $span, 2))));
}

// Cross-process pacing: at most ~1 Nominatim request per second site-wide.
function map_nominatim_pace(): void {
    $dir = sys_get_temp_dir() . '/duckfind-rl';
    if (!is_dir($dir)) @mkdir($dir, 0700, true);
    $fp = @fopen($dir . '/.nominatim', 'c+');
    if ($fp === false) return;
    if (flock($fp, LOCK_EX)) {
        $wait = 1.1 - (microtime(true) - (float)stream_get_contents($fp));
        if ($wait > 0 && $wait <= 1.1) usleep((int)($wait * 1e6));
        ftruncate($fp, 0); rewind($fp); fwrite($fp, (string)microtime(true));
        fflush($fp); flock($fp, LOCK_UN);
    }
    fclose($fp);
}

// ============================================================================
// GIF mode: stitch tiles around the centre and emit one image.
// ============================================================================
if (isset($_GET['gif'])) {
    if (!df_rate('map')) { img_blank(); }
    [$lat, $lon, $z] = map_clamp((float)($_GET['lat'] ?? 0), (float)($_GET['lon'] ?? 0), (int)($_GET['z'] ?? 4));
    $mode = strtolower($_GET['im'] ?? 'color');
    if (!in_array($mode, ['color', 'gray', 'bw'], true)) $mode = 'color';

    $ckey = 'map2:' . $mode . ':' . $z . ':' . round($lat, 5) . ':' . round($lon, 5);
    if (($hit = df_cache_get($ckey, 604800)) !== null) {
        header('Content-Type: image/gif');
        header('Cache-Control: public, max-age=86400');
        echo $hit; exit;
    }

    [$cx, $cy] = map_px($lat, $lon, $z);
    $x0 = (int)round($cx - MAP_W / 2);
    $y0 = (int)round($cy - MAP_H / 2);
    $tiles = 2 ** $z;

    $img = imagecreatetruecolor(MAP_W, MAP_H);
    imagefill($img, 0, 0, imagecolorallocate($img, 221, 221, 221));
    for ($tx = (int)floor($x0 / 256); $tx * 256 < $x0 + MAP_W; $tx++) {
        for ($ty = (int)floor($y0 / 256); $ty * 256 < $y0 + MAP_H; $ty++) {
            if ($ty < 0 || $ty >= $tiles) continue;      // past the poles: leave grey
            $wx = (($tx % $tiles) + $tiles) % $tiles;    // wrap the antimeridian
            $tkey = 'tile:' . $z . ':' . $wx . ':' . $ty;
            $png = df_cache_get($tkey, 604800);
            if ($png === null) {
                $r = http_get('https://tile.openstreetmap.org/' . $z . '/' . $wx . '/' . $ty . '.png',
                              300000, MAP_UA);
                if ($r === null || !preg_match('#^image/#', $r['ctype'])) continue;
                $png = $r['body'];
                df_cache_put($tkey, $png);
            }
            $t = @imagecreatefromstring($png);
            if ($t === false) continue;
            imagecopy($img, $t, $tx * 256 - $x0, $ty * 256 - $y0, 0, 0, 256, 256);
            imagedestroy($t);
        }
    }

    // centre marker: red dot in a white ring, drawn on the truecolor canvas so
    // it survives every palette mode (becomes a solid black dot in 1-bit)
    imagefilledellipse($img, (int)(MAP_W / 2), (int)(MAP_H / 2), 13, 13,
                       imagecolorallocate($img, 255, 255, 255));
    imagefilledellipse($img, (int)(MAP_W / 2), (int)(MAP_H / 2), 9, 9,
                       imagecolorallocate($img, 204, 0, 0));

    if ($mode === 'gray') {
        imagefilter($img, IMG_FILTER_GRAYSCALE);
        imagetruecolortopalette($img, false, 64);
    } elseif ($mode === 'bw') {
        // map tiles are mostly pale, so 1-bit needs far more contrast than a
        // photo before dithering or everything melts into white
        imagefilter($img, IMG_FILTER_GRAYSCALE);
        imagefilter($img, IMG_FILTER_CONTRAST, -45);
        imagetruecolortopalette($img, true, 2);
    } else {
        // no dithering for the colour map: OSM tiles are flat-shaded already,
        // and dithering just fuzzes the street labels
        imagetruecolortopalette($img, false, 255);
    }

    ob_start();
    imagegif($img);
    $gif = ob_get_clean();
    imagedestroy($img);
    df_cache_put($ckey, $gif);
    header('Content-Type: image/gif');
    header('Cache-Control: public, max-age=86400');
    echo $gif; exit;
}

function img_blank(): void {
    header('Content-Type: image/gif');
    header('Cache-Control: public, max-age=3600');
    $im = imagecreate(1, 1);
    imagecolortransparent($im, imagecolorallocate($im, 255, 255, 255));
    imagegif($im);
    imagedestroy($im);
    exit;
}

// ============================================================================
// HTML mode: search box, map view with pan/zoom links, directions.
// ============================================================================
if (!df_rate('map')) df_rate_block();
header('Content-Type: text/html; charset=iso-8859-1');

$q    = df_input('q');
$from = df_input('from');
$to   = df_input('to');
$mode = strtolower($_GET['im'] ?? ($_COOKIE['df_mode'] ?? 'color'));
if (!in_array($mode, ['color', 'gray', 'bw'], true)) $mode = 'color';

echo page_head(DUCKFIND_NAME . ' maps' . ($q !== '' ? ' - ' . $q : ''));
echo '<form action="/map.php" method="get"><a href="/"><b>' . DUCKFIND_NAME . '</b></a>&nbsp;&nbsp;'
   . 'Map of: <input type="text" name="q" size="22" value="' . e($q) . '">&nbsp;'
   . '<input type="submit" value="Go"></form>';
echo '<form action="/map.php" method="get">Directions: '
   . '<input type="text" name="from" size="14" value="' . e($from) . '"> to '
   . '<input type="text" name="to" size="14" value="' . e($to) . '">&nbsp;'
   . '<input type="submit" value="Go"></form><hr>';

// --- directions -------------------------------------------------------------
if ($from !== '' && $to !== '') {
    $a = map_geocode($from);
    $b = map_geocode($to, $a);
    if (!$a || !$b) {
        $bad = !$a ? $from : $to;
        echo '<p>Could not find <b>' . e($bad) . '</b>. Try a city or town name.</p>' . page_foot();
        exit;
    }
    $r = http_get_cached('https://router.project-osrm.org/route/v1/driving/'
        . $a['lon'] . ',' . $a['lat'] . ';' . $b['lon'] . ',' . $b['lat']
        . '?overview=false&steps=true', 86400, 3000000);
    $j = $r ? json_decode($r['body'], true) : null;
    $route = $j['routes'][0] ?? null;
    if (!$route) {
        echo '<p>No drivable route found between <b>' . e($a['name']) . '</b> and <b>'
           . e($b['name']) . '</b>.</p>' . page_foot();
        exit;
    }
    $mi  = $route['distance'] / 1609.344;
    $min = (int)round($route['duration'] / 60);
    $dur = $min >= 60 ? intdiv($min, 60) . ' hr ' . ($min % 60) . ' min' : $min . ' min';
    echo '<h2>' . e($a['name']) . ' &rarr; ' . e($b['name']) . '</h2>';
    echo '<p><b>' . round($mi, $mi < 10 ? 1 : 0) . ' miles</b> &middot; about ' . $dur
       . ' driving</p><ol>';
    foreach ($route['legs'] as $leg) {
        foreach ($leg['steps'] as $s) {
            echo '<li>' . e(map_step_text($s)) . '</li>';
        }
    }
    echo '</ol>';
    echo '<p><font size="1">[<a href="/map.php?q=' . urlencode($to) . '">map of '
       . e($b['name']) . '</a>] &middot; routing by <a href="http://project-osrm.org/">OSRM</a>, '
       . 'data &copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> '
       . 'contributors</font></p>';
    echo page_foot(); exit;
}

// --- map view ----------------------------------------------------------------
$name = '';
if ($q !== '') {
    $g = map_geocode($q);
    if (!$g) {
        echo '<p>Could not find <b>' . e($q) . '</b>. Try a place name or a street address.</p>'
           . page_foot();
        exit;
    }
    $lat = $g['lat']; $lon = $g['lon']; $name = $g['name'];
    $z = (int)($_GET['z'] ?? ($g['zoom'] ?? 12));
} elseif (isset($_GET['lat'], $_GET['lon'])) {
    $lat = (float)$_GET['lat']; $lon = (float)$_GET['lon'];
    $z = (int)($_GET['z'] ?? 12);
} else {
    echo '<p>Enter a place or street address above &mdash; or get driving directions '
       . 'between two places.</p>'
       . '<p><font size="1">Try: <a href="/map.php?q=Boston">Boston</a> &middot; '
       . '<a href="/map.php?q=Tokyo">Tokyo</a> &middot; '
       . '<a href="/map.php?q=Grand+Canyon">Grand Canyon</a></font></p>';
    echo page_foot(); exit;
}
[$lat, $lon, $z] = map_clamp($lat, $lon, $z);

// pan targets: half a viewport in each direction, computed in pixel space so
// panning feels uniform at every latitude
[$cx, $cy] = map_px($lat, $lon, $z);
$pan = function (float $dx, float $dy) use ($cx, $cy, $z, $mode): string {
    [$la, $lo] = map_lonlat($cx + $dx, $cy + $dy, $z);
    return '/map.php?lat=' . round($la, 5) . '&amp;lon=' . round($lo, 5) . '&amp;z=' . $z
         . '&amp;im=' . $mode;
};
$zoom = function (int $nz) use ($lat, $lon, $mode): string {
    return '/map.php?lat=' . round($lat, 5) . '&amp;lon=' . round($lon, 5) . '&amp;z=' . $nz
         . '&amp;im=' . $mode;
};

if ($name !== '') echo '<h2>' . e($name) . '</h2>';
echo '<p><a href="' . $pan(0, -MAP_H / 2) . '">north</a> &middot; '
   . '<a href="' . $pan(0, MAP_H / 2) . '">south</a> &middot; '
   . '<a href="' . $pan(-MAP_W / 2, 0) . '">west</a> &middot; '
   . '<a href="' . $pan(MAP_W / 2, 0) . '">east</a> &nbsp;|&nbsp; '
   . ($z < MAP_ZMAX ? '<a href="' . $zoom($z + 1) . '"><b>zoom in</b></a>' : 'zoom in') . ' &middot; '
   . ($z > MAP_ZMIN ? '<a href="' . $zoom($z - 1) . '"><b>zoom out</b></a>' : 'zoom out') . '</p>';
$levels = ['world' => 3, 'country' => 5, 'region' => 8, 'city' => 12, 'street' => 15];
$zrow = [];
foreach ($levels as $label => $lz) {
    $zrow[] = $z === $lz ? '<b>' . $label . '</b>' : '<a href="' . $zoom($lz) . '">' . $label . '</a>';
}
echo '<p><font size="1">zoom to: ' . implode(' &middot; ', $zrow) . '</font></p>';
echo '<a href="/map.php/c/' . round($lat, 5) . '/' . round($lon, 5) . '/' . $z . '/' . $mode . '">'
   . '<img src="/map.php?gif=1&amp;lat=' . round($lat, 5) . '&amp;lon=' . round($lon, 5)
   . '&amp;z=' . $z . '&amp;im=' . $mode . '" width="' . MAP_W . '" height="' . MAP_H
   . '" border="1" ismap alt="Map"></a>';
echo '<br><font size="1"><b>Click anywhere on the map to re-centre it there.</b> '
   . 'map data &copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> '
   . 'contributors</font>';
if ($name !== '') {
    echo '<p><font size="1">[<a href="/map.php?q=' . urlencode($q) . '&amp;from=' . urlencode($q)
       . '">directions from here</a>] [<a href="/map.php?q=' . urlencode($q) . '&amp;to='
       . urlencode($q) . '">directions to here</a>]</font></p>';
}
echo page_foot();

// Turn one OSRM step into a plain-English instruction.
function map_step_text(array $s): string {
    $m    = $s['maneuver'] ?? [];
    $type = $m['type'] ?? '';
    $mod  = $m['modifier'] ?? '';
    $road = trim((string)($s['name'] ?? ''));
    $onto = $road !== '' ? ' onto ' . $road : '';
    switch ($type) {
        case 'depart':      $txt = 'Start' . ($road !== '' ? ' on ' . $road : ''); break;
        case 'arrive':      return 'Arrive at your destination';
        case 'roundabout':
        case 'rotary':      $txt = 'At the roundabout take exit ' . (int)($m['exit'] ?? 1) . $onto; break;
        case 'merge':       $txt = 'Merge' . ($mod !== '' ? ' ' . $mod : '') . $onto; break;
        case 'on ramp':     $txt = 'Take the ramp' . $onto; break;
        case 'off ramp':    $txt = 'Take the exit' . $onto; break;
        case 'fork':        $txt = 'Keep ' . ($mod ?: 'ahead') . ($road !== '' ? ' toward ' . $road : ''); break;
        case 'end of road': $txt = 'Turn ' . ($mod ?: 'ahead') . $onto; break;
        case 'continue':
        case 'new name':    $txt = 'Continue' . $onto; break;
        default:            $txt = ($mod !== '' ? 'Turn ' . $mod : 'Continue') . $onto;
    }
    $mtr = (float)($s['distance'] ?? 0);
    if ($mtr >= 160) {
        $mi  = $mtr / 1609.344;
        $txt .= ' - ' . ($mi < 10 ? round($mi, 1) : round($mi)) . ' mi';
    } elseif ($mtr > 0) {
        $txt .= ' - ' . (int)(round($mtr * 3.28084 / 10) * 10) . ' ft';
    }
    return $txt;
}
