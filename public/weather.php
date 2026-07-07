<?php
// DuckFind weather — plain-HTML forecast via Open-Meteo (no API key needed).
require __DIR__ . '/lib.php';
if (!df_rate('search')) df_rate_block();
header('Content-Type: text/html; charset=iso-8859-1');

$place = df_input('q');
$unit  = (strtolower($_GET['u'] ?? 'f') === 'c') ? 'c' : 'f';
$tunit = $unit === 'c' ? 'celsius' : 'fahrenheit';
$tsym  = $unit === 'c' ? 'C' : 'F';

echo page_head(DUCKFIND_NAME . ' weather' . ($place !== '' ? ' - ' . $place : ''));
echo '<form action="/weather.php" method="get"><a href="/"><b>' . DUCKFIND_NAME . '</b></a>&nbsp;&nbsp;'
   . 'Weather for: <input type="text" name="q" size="22" value="' . e($place) . '">&nbsp;'
   . '<input type="submit" value="Go"></form><hr>';

if ($place === '') {
    echo '<p>Enter a city or place name above for a 5-day forecast.</p>';
    echo page_foot(); exit;
}

$g = http_get('https://geocoding-api.open-meteo.com/v1/search?count=1&language=en&name=' . urlencode($place));
$geo = $g ? json_decode($g['body'], true) : null;
if (!$geo || empty($geo['results'][0]['latitude'])) {
    echo '<p>Could not find <b>' . e($place) . '</b>. Try a city name.</p>' . page_foot(); exit;
}
$loc  = $geo['results'][0];
$name = $loc['name']
      . (!empty($loc['admin1']) ? ', ' . $loc['admin1'] : '')
      . (!empty($loc['country']) ? ', ' . $loc['country'] : '');

$f = http_get('https://api.open-meteo.com/v1/forecast?latitude=' . $loc['latitude']
    . '&longitude=' . $loc['longitude']
    . '&current=temperature_2m,apparent_temperature,weather_code,wind_speed_10m,relative_humidity_2m'
    . '&daily=weather_code,temperature_2m_max,temperature_2m_min'
    . '&temperature_unit=' . $tunit . '&wind_speed_unit=mph&timezone=auto&forecast_days=5');
$wx = $f ? json_decode($f['body'], true) : null;
if (!$wx || empty($wx['current'])) {
    echo '<p>Weather is temporarily unavailable. Please try again.</p>' . page_foot(); exit;
}

$c = $wx['current'];
$other = $unit === 'c' ? 'f' : 'c';
echo '<h2>' . e($name) . '</h2>';
echo '<font size="1">[<a href="/weather.php?q=' . e(urlencode($place)) . '&amp;u=' . $other . '">show in &deg;'
   . strtoupper($other) . '</a>]</font>';
echo '<p><font size="5"><b>' . round($c['temperature_2m']) . '&deg;' . $tsym . '</b></font> &nbsp; '
   . e(df_wmo((int)$c['weather_code'])) . '<br>';
echo 'Feels like ' . round($c['apparent_temperature']) . '&deg;' . $tsym
   . ' &middot; Humidity ' . round($c['relative_humidity_2m']) . '%'
   . ' &middot; Wind ' . round($c['wind_speed_10m']) . ' mph</p>';

echo '<h3>Next 5 days</h3>';
echo '<table border="1" cellpadding="4" cellspacing="0">';
echo '<tr><th>Day</th><th>Conditions</th><th>High</th><th>Low</th></tr>';
$days = $wx['daily'];
for ($i = 0; $i < count($days['time']); $i++) {
    $dow = df_dow($days['time'][$i]);
    echo '<tr><td><b>' . e($dow) . '</b></td><td>' . e(df_wmo((int)$days['weather_code'][$i])) . '</td>'
       . '<td align="right">' . round($days['temperature_2m_max'][$i]) . '&deg;</td>'
       . '<td align="right">' . round($days['temperature_2m_min'][$i]) . '&deg;</td></tr>';
}
echo '</table>';
echo '<p><font size="1">Data: <a href="https://open-meteo.com/">Open-Meteo</a></font></p>';
echo page_foot();

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
