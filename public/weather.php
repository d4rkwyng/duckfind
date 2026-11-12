<?php
// DuckFind weather — plain-HTML forecast via Open-Meteo (no API key needed),
// with the US National Weather Service as a fallback for US locations.
require __DIR__ . '/lib.php';
if (!df_rate('search')) df_rate_block();
header('Content-Type: text/html; charset=iso-8859-1');

$place = df_input('q');
$uraw = $_GET['u'] ?? 'f';
$unit  = (is_string($uraw) && strtolower($uraw) === 'c') ? 'c' : 'f';
$tsym  = $unit === 'c' ? 'C' : 'F';

echo page_head(DUCKFIND_NAME . ' - weather' . ($place !== '' ? ': ' . $place : ''));
echo '<form action="/weather.php" method="get">' . df_brand_link() . '&nbsp;&nbsp;'
   . 'Weather for: <input type="text" name="q" size="22" value="' . e($place) . '">&nbsp;'
   . '<input type="submit" value="Go"></form><hr>';

if ($place === '') {
    echo '<p>Enter a city or place name above for a 5-day forecast.</p>';
    echo page_foot(); exit;
}

$geo = df_wx_geocode($place);
if ($geo === null) {
    echo '<p>The weather service is temporarily unavailable. Please try again shortly.</p>' . page_foot(); exit;
}
// isset, not empty(): latitude 0 (the equator) is a real place
if (!isset($geo['results'][0]['latitude'], $geo['results'][0]['longitude'])) {
    echo '<p>Could not find <b>' . e($place) . '</b>. Try a city name.</p>' . page_foot(); exit;
}
$loc  = $geo['results'][0];
$name = $loc['name']
      . (!empty($loc['admin1']) ? ', ' . $loc['admin1'] : '')
      . (!empty($loc['country']) ? ', ' . $loc['country'] : '');

$fc = wx_forecast($loc, $unit);
if ($fc === null) {
    echo '<p>Weather is temporarily unavailable. Please try again.</p>' . page_foot(); exit;
}

$other = $unit === 'c' ? 'f' : 'c';
$wunit = $unit === 'c' ? 'km/h' : 'mph';
echo '<h2>' . e($name) . '</h2>';
echo '<font size="1">[<a href="/weather.php?q=' . e(urlencode($place)) . '&amp;u=' . $other . '">show in &deg;'
   . strtoupper($other) . '</a>]</font>';
if ($fc['stale_at'] !== null) {
    echo '<p><font size="1">As of ' . gmdate('H:i', $fc['stale_at']) . ' UTC (the weather service is not '
       . 'answering right now).</font></p>';
}
if ($fc['src'] === 'om') {
    $wx = $fc['data'];
    $c = $wx['current'];
    echo '<p><font size="5"><b>' . round($c['temperature_2m'] ?? 0) . '&deg;' . $tsym . '</b></font> &nbsp; '
       . e(df_wmo((int)($c['weather_code'] ?? -1))) . '<br>';
    echo 'Feels like ' . round($c['apparent_temperature'] ?? 0) . '&deg;' . $tsym
       . ' &middot; Humidity ' . round($c['relative_humidity_2m'] ?? 0) . '%'
       . ' &middot; Wind ' . round($c['wind_speed_10m'] ?? 0) . ' ' . $wunit . '</p>';
    $rows = [];
    $days = $wx['daily'] ?? [];
    for ($i = 0; $i < count($days['time'] ?? []); $i++) {
        $rows[] = [df_dow($days['time'][$i]), df_wmo((int)($days['weather_code'][$i] ?? -1)),
                   $days['temperature_2m_max'][$i] ?? null, $days['temperature_2m_min'][$i] ?? null];
    }
    $credit = 'Data: <a href="https://open-meteo.com/">Open-Meteo</a>';
} else {
    // US National Weather Service: 12-hour periods ("Today", "Tonight", ...)
    $ps = $fc['data']['properties']['periods'];
    $p0 = $ps[0];
    echo '<p><font size="5"><b>' . wx_nws_temp($p0, $unit) . '&deg;' . $tsym . '</b></font> &nbsp; '
       . e((string)($p0['shortForecast'] ?? '')) . '<br>';
    echo e((string)($p0['name'] ?? '')) . ' &middot; Wind ' . e(wx_nws_wind($p0, $unit))
       . (!empty($p0['windDirection']) ? ' ' . e((string)$p0['windDirection']) : '') . '</p>';
    $rows = wx_nws_rows($ps, $unit);
    $credit = 'Forecast: <a href="https://www.weather.gov/">US National Weather Service</a>';
}

echo '<h3>Forecast (&deg;' . $tsym . ')</h3>';
echo '<table border="1" cellpadding="4" cellspacing="0">';
echo '<tr><th>Day</th> <th>Conditions</th> <th>High</th> <th>Low</th></tr>';
foreach (array_slice($rows, 0, 5) as $r) {
    // a space between cells so table-less browsers don't run them together
    echo '<tr><td><b>' . e($r[0]) . '</b></td> <td>' . e($r[1]) . '</td> '
       . '<td align="right">' . ($r[2] === null ? '-' : round($r[2]) . '&deg;') . '</td> '
       . '<td align="right">' . ($r[3] === null ? '-' : round($r[3]) . '&deg;') . '</td></tr>';
}
echo '</table>';
echo '<p><font size="1">' . $credit . '</font></p>';
echo page_foot();

// --- forecast sources (2026-11-12) ---------------------------------------------
// Order: Open-Meteo (fresh copy within 30 min, else a live fetch) -> for US
// locations, the US National Weather Service -> the last good forecast from
// either, up to 6 hours old, shown with an "as of" note -> null (error).
// Everything is cached per location and unit; failures never are.
// Returns ['src' => 'om'|'nws', 'data' => array, 'stale_at' => null|int].
// (Literal 1800 s fresh / 21600 s stale below, not file-level consts: this
// page's code runs before a const declared down here would exist.)
function wx_forecast(array $loc, string $unit): ?array {
    $lat = round((float)$loc['latitude'], 4); $lon = round((float)$loc['longitude'], 4);
    $lastKey = 'wxlast:' . $lat . ',' . $lon . ':' . $unit;
    $last = json_decode((string)df_cache_get($lastKey, 21600), true);
    if (is_array($last) && ($last['src'] ?? '') === 'om' && (int)($last['at'] ?? 0) > time() - 1800) {
        return ['src' => 'om', 'data' => $last['data'], 'stale_at' => null];
    }
    $om = wx_openmeteo($lat, $lon, $unit);
    if ($om !== null) {
        df_cache_put($lastKey, json_encode(['src' => 'om', 'data' => $om, 'at' => time()]));
        return ['src' => 'om', 'data' => $om, 'stale_at' => null];
    }
    if (wx_is_us($loc)) {
        $nws = wx_nws($lat, $lon);
        if ($nws !== null) {
            df_cache_put($lastKey, json_encode(['src' => 'nws', 'data' => $nws, 'at' => time()]));
            return ['src' => 'nws', 'data' => $nws, 'stale_at' => null];
        }
    }
    if (is_array($last) && isset($last['data'], $last['src'], $last['at'])) {
        return ['src' => (string)$last['src'], 'data' => $last['data'], 'stale_at' => (int)$last['at']];
    }
    return null;
}

// Every forecast fetch goes through here. Test seam: tests/run.php sets
// $GLOBALS['DF_TEST_WX'] to a callable instead of touching the network.
function wx_get(string $url, string $ua = '', array $headers = []): ?array {
    if (isset($GLOBALS['DF_TEST_WX'])) return ($GLOBALS['DF_TEST_WX'])($url);
    return http_get($url, 3000000, $ua, null, 6, $headers);
}

function wx_openmeteo(float $lat, float $lon, string $unit): ?array {
    $r = wx_get('https://api.open-meteo.com/v1/forecast?latitude=' . $lat . '&longitude=' . $lon
        . '&current=temperature_2m,apparent_temperature,weather_code,wind_speed_10m,relative_humidity_2m'
        . '&daily=weather_code,temperature_2m_max,temperature_2m_min'
        . '&temperature_unit=' . ($unit === 'c' ? 'celsius' : 'fahrenheit')
        . '&wind_speed_unit=' . ($unit === 'c' ? 'kmh' : 'mph') . '&timezone=auto&forecast_days=5');
    if ($r === null || (int)($r['status'] ?? 200) !== 200) return null;
    $wx = json_decode((string)$r['body'], true);
    return (is_array($wx) && !empty($wx['current'])) ? $wx : null;
}

// US, from the geocoder's country code: the 50 states and DC (US) plus the
// territories NWS forecasts (Puerto Rico, Virgin Islands, Guam, American
// Samoa, Northern Marianas). Bounding boxes only when no code came back.
function wx_is_us(array $loc): bool {
    $cc = strtoupper((string)($loc['country_code'] ?? ''));
    if ($cc !== '') return in_array($cc, ['US', 'PR', 'VI', 'GU', 'AS', 'MP'], true);
    $la = (float)$loc['latitude']; $lo = (float)$loc['longitude'];
    $boxes = [[24.4, 49.4, -125.0, -66.9],   // lower 48
              [51.2, 71.5, -179.9, -129.9],  // Alaska
              [18.9, 22.3, -160.3, -154.8],  // Hawaii
              [17.8, 18.6, -67.3, -65.2]];   // Puerto Rico
    foreach ($boxes as [$a, $b, $c, $d]) if ($la >= $a && $la <= $b && $lo >= $c && $lo <= $d) return true;
    return false;
}

// NWS (api.weather.gov), per https://www.weather.gov/documentation/services-web-api:
// an identifying User-Agent is required (the site URL, never a personal
// address); /points/{lat},{lon} gives properties.forecast, the 12-hour-period
// forecast URL. Points rarely change (served with max-age 86400): cached 7
// days. Forecasts (served with s-maxage 3600): cached 30 min.
function wx_nws_ua(): string {
    return 'DuckFind/1.0 (+' . df_cfg('base_url', 'http://duckfind.com') . ')';
}
function wx_nws(float $lat, float $lon): ?array {
    $hdr = ['Accept: application/geo+json'];
    $pk = 'wxnwspts:' . round($lat, 4) . ',' . round($lon, 4);
    $furl = (string)df_cache_get($pk, 604800);
    if ($furl === '') {
        $r = wx_get('https://api.weather.gov/points/' . round($lat, 4) . ',' . round($lon, 4), wx_nws_ua(), $hdr);
        if ($r === null || (int)($r['status'] ?? 200) !== 200) return null;
        $j = json_decode((string)$r['body'], true);
        $furl = is_array($j) ? (string)($j['properties']['forecast'] ?? '') : '';
        if (!preg_match('#^https://api\.weather\.gov/#', $furl)) return null;
        df_cache_put($pk, $furl);
    }
    $fk = 'wxnwsfc:' . $furl;
    if (($c = df_cache_get($fk, 1800)) !== null) {
        $d = json_decode($c, true);
        if (is_array($d)) return $d;
    }
    $r = wx_get($furl, wx_nws_ua(), $hdr);
    if ($r === null || (int)($r['status'] ?? 200) !== 200) return null;
    $d = json_decode((string)$r['body'], true);
    if (!is_array($d) || empty($d['properties']['periods'][0])) return null;
    df_cache_put($fk, json_encode($d));
    return $d;
}
// NWS temperatures are Fahrenheit; convert for u=c.
function wx_nws_temp(array $p, string $unit): int {
    $t = (float)($p['temperature'] ?? 0);
    if (strtoupper((string)($p['temperatureUnit'] ?? 'F')) === 'C') $t = $t * 9 / 5 + 32;
    return (int)round($unit === 'c' ? ($t - 32) * 5 / 9 : $t);
}
// "5 to 10 mph" -> "8 to 16 km/h" for u=c
function wx_nws_wind(array $p, string $unit): string {
    $w = (string)($p['windSpeed'] ?? '');
    if ($unit !== 'c') return $w;
    return trim(str_replace('mph', 'km/h', preg_replace_callback('/\d+(?:\.\d+)?/', function ($m) {
        return (string)(int)round((float)$m[0] * 1.609344);
    }, $w)));
}
// Pair the 12-hour periods into day rows [name, conditions, high, low]. A
// forecast that starts at night ("Tonight") gives a first row with only a low.
function wx_nws_rows(array $ps, string $unit): array {
    $rows = [];
    $cur = null;
    foreach ($ps as $p) {
        if (!is_array($p)) continue;
        if (!empty($p['isDaytime'])) {
            if ($cur !== null) $rows[] = $cur;
            $cur = [(string)($p['name'] ?? ''), (string)($p['shortForecast'] ?? ''), wx_nws_temp($p, $unit), null];
        } else {
            if ($cur === null) {
                $rows[] = [(string)($p['name'] ?? ''), (string)($p['shortForecast'] ?? ''), null, wx_nws_temp($p, $unit)];
            } else {
                $cur[3] = wx_nws_temp($p, $unit);
                $rows[] = $cur; $cur = null;
            }
        }
    }
    if ($cur !== null) $rows[] = $cur;
    return $rows;
}

// Open-Meteo's geocoding endpoint occasionally hiccups the same unpredictable
// way Gutendex/dictionaryapi.dev/frankfurter.app do -- retry a few times
// before concluding anything. Returns null only for a genuine fetch failure
// (distinct from a valid response with zero results, i.e. a real place that
// just doesn't exist), so a transient upstream failure isn't reported as
// "couldn't find that place" -- the same bug shape already fixed in
// define.php/calc.php, map.php already has its own fallback-geocoder version
// of this same discipline.
//
// Retry only on a true fetch failure (no response, or a body that isn't even
// JSON) -- NOT on missing a "results" key or on HTTP status. Confirmed live:
// a genuinely nonexistent place returns a real 200 with NO "results" key at
// all (just `{"generationtime_ms":...}`), not an empty array -- the first
// version of this fix required isset($j['results']), which meant a real
// "place not found" got treated as an incomplete response, retried to
// exhaustion, and misreported as "temporarily unavailable". Any decodable
// JSON object is a completed, trustworthy answer; the caller already checks
// for a real results[0] itself.
// Place lookups are cached 7 days (only real hits: a miss is never cached).
function df_wx_geocode(string $place): ?array {
    $key = 'wxgeo:' . mb_strtolower(trim($place));
    if (($c = df_cache_get($key, 604800)) !== null) {
        $d = json_decode($c, true);
        if (is_array($d)) return $d;
    }
    $url = 'https://geocoding-api.open-meteo.com/v1/search?count=1&language=en&name=' . urlencode($place);
    for ($i = 0; $i < 3; $i++) {
        if ($i > 0) usleep(400000);
        $r = isset($GLOBALS['DF_TEST_WX']) ? ($GLOBALS['DF_TEST_WX'])($url) : http_get($url, 3000000, '', null, 4);
        if ($r === null) continue;
        $j = json_decode($r['body'], true);
        if (is_array($j)) {
            if (isset($j['results'][0]['latitude'])) df_cache_put($key, json_encode($j));
            return $j;
        }
    }
    return null;
}

// WMO weather-interpretation codes -> plain English
function df_wmo(int $c): string {
    static $m = [
        0 => 'Clear sky', 1 => 'Mainly clear', 2 => 'Partly cloudy', 3 => 'Overcast',
        45 => 'Fog', 48 => 'Rime fog',
        51 => 'Light drizzle', 53 => 'Drizzle', 55 => 'Heavy drizzle',
        56 => 'Freezing drizzle', 57 => 'Freezing drizzle',
        61 => 'Light rain', 63 => 'Rain', 65 => 'Heavy rain',
        66 => 'Freezing rain', 67 => 'Freezing rain',
        71 => 'Light snow', 73 => 'Snow', 75 => 'Heavy snow', 77 => 'Snow grains',
        80 => 'Light showers', 81 => 'Showers', 82 => 'Violent showers',
        85 => 'Snow showers', 86 => 'Snow showers',
        95 => 'Thunderstorm', 96 => 'Thunderstorm w/ hail', 99 => 'Thunderstorm w/ hail',
    ];
    return $m[$c] ?? 'Unknown';
}

// YYYY-MM-DD -> weekday name without relying on locale
function df_dow(string $ymd): string {
    static $names = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
    [$y, $m, $d] = array_map('intval', explode('-', $ymd));
    // Zeller-ish via mktime is fine on the server
    $ts = @mktime(12, 0, 0, $m, $d, $y);
    return $ts ? $names[(int)date('w', $ts)] : $ymd;
}
