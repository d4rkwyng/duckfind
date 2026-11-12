<?php
// DuckFind calculator & unit converter — server-side math for machines whose
// calculator desk accessory predates the euro. Two input shapes, auto-detected:
//   "2 + 2 * (14 - 3) ^ 2"       arithmetic (own shunting-yard parser, no eval)
//   "5 mi to km" / "72 f to c"   unit conversion, plus live currency
//   "100 usd to jpy"             via Frankfurter (ECB rates, cached 12 h)
require __DIR__ . '/lib.php';

if (!df_rate('search')) df_rate_block();
header('Content-Type: text/html; charset=iso-8859-1');

$q = trim(df_input('q'));

echo page_head(DUCKFIND_NAME . ' - calculator' . ($q !== '' ? ' - ' . $q : ''));
echo '<form action="/calc.php" method="get">' . df_brand_link() . '&nbsp;&nbsp;'
   . 'Calculate: <input type="text" name="q" size="30" value="' . e($q) . '">&nbsp;'
   . '<input type="submit" value="Go"></form><hr>';

if ($q === '') {
    echo '<p>Type a sum or a conversion:</p>'
       . '<p><font size="1"><a href="/calc.php?q=' . urlencode('2+2*(14-3)^2') . '"><tt>2+2*(14-3)^2</tt></a> &middot; '
       . '<a href="/calc.php?q=' . urlencode('26.2 mi to km') . '"><tt>26.2 mi to km</tt></a> &middot; '
       . '<a href="/calc.php?q=' . urlencode('72 f to c') . '"><tt>72 f to c</tt></a> &middot; '
       . '<a href="/calc.php?q=' . urlencode('100 usd to jpy') . '"><tt>100 usd to jpy</tt></a></font></p>';
    echo page_foot(); exit;
}

// units may be two words ("fl oz") or carry a slash ("km/h")
if (preg_match('/^(-?[\d.,]+)\s*([a-z\x{00B0}\/]+(?:\s(?!to\b|in\b)[a-z]+)?)\s+(?:to|in)\s+([a-z\x{00B0}\/]+(?:\s[a-z]+)?)$/iu', $q, $m)) {
    $num = df_parse_number($m[1]);
    $out = $num === null ? ['err' => 'Could not read the number "' . $m[1] . '".']
                         : df_convert($num, $m[2], $m[3]);
} else {
    $out = df_calc($q);
}
echo '<h2>' . e($q) . '</h2>';
echo isset($out['err'])
    ? '<p><font color="#AA0000">' . e($out['err']) . '</font></p>'
    : '<p><font size="5"><b>= ' . e($out['res']) . '</b></font>'
      . (isset($out['note']) ? '<br><font size="1">' . e($out['note']) . '</font>' : '') . '</p>';
echo page_foot();

// --- number formatting: up to 8 significant digits, no trailing zeros --------
function df_num(float $n): string {
    if (!is_finite($n)) return 'infinity';
    // Strip trailing zeros only from a FRACTIONAL part. A blind rtrim('0')
    // turned "100" into "1" (50+50 = 1, 1 km = 1 m) and "1.0E+20" into
    // "1.0E+2" (exponent digits are not trailing zeros).
    // whole numbers below 1e15 print exactly (%G would show 123456789 as 1.2345679E+8)
    if (abs($n) < 1e15 && floor($n) == $n) return sprintf('%.0f', $n == 0 ? 0 : $n);
    $s = sprintf('%.8G', $n);
    $exp = '';
    if (($p = strpos($s, 'E')) !== false) { $exp = substr($s, $p); $s = substr($s, 0, $p); }
    if (strpos($s, '.') !== false) $s = rtrim(rtrim($s, '0'), '.');
    if ($s === '-0') $s = '0';
    return $s . $exp;
}

// One number as typed, or null if it isn't one. "1,234" and "1,234,567.5" are
// thousands groups; "1,5" and "2,75" are decimal commas (they used to become
// 15 and 275, so "1,5 km" was 15 km); "1.2.3" and "1,2345" are rejected rather
// than half-read.
function df_parse_number(string $t) {
    $t = trim($t);
    if (preg_match('/^-?\d+(?:\.\d+)?$|^-?\.\d+$/', $t)) return (float)$t;
    if (preg_match('/^-?\d{1,3}(?:,\d{3})+(?:\.\d+)?$/', $t)) return (float)str_replace(',', '', $t);
    if (preg_match('/^-?\d+,\d{1,2}$/', $t)) return (float)str_replace(',', '.', $t);
    return null;
}

// --- arithmetic: tokenize + shunting-yard + RPN eval. No eval(), ever. -------
function df_calc(string $expr): array {
    if (!preg_match('/^[\d\s+\-*\/%^().,x]+$/i', $expr)) {
        return ['err' => 'Only numbers and + - * / % ^ ( ) are supported.'];
    }
    if (preg_match('/\b0x[0-9a-f]/i', $expr)) return ['err' => 'Hex numbers (0x...) are not supported.'];
    // commas: thousands groups first ("1,234"), then decimal commas ("1,5");
    // any comma left after that is ambiguous, so say so instead of guessing
    $expr = preg_replace('/(?<=\d),(?=\d{3}(?!\d))/', '', $expr);
    $expr = preg_replace('/(?<=\d),(?=\d{1,2}(?!\d))/', '.', $expr);
    if (strpos($expr, ',') !== false) return ['err' => 'Could not read the commas in that expression.'];
    if (preg_match('/\d*\.\d*\.\d/', $expr)) return ['err' => 'Could not read that expression.'];
    $expr = str_ireplace('x', '*', $expr);
    preg_match_all('/\d*\.\d+|\d+|[+\-*\/%^()]/', $expr, $mm);
    $tok = $mm[0];
    if (!$tok || count($tok) > 100) return ['err' => 'Could not read that expression.'];

    // shunting-yard; 'u' is unary minus. u sits between ^ and */% so that
    // -3^2 = -(3^2) = -9 (maths convention) while 2*-3 and 2^-3 still work;
    // as a prefix operator it pushes without popping (it has no left operand).
    $prec = ['^' => 4, 'u' => 3.5, '*' => 3, '/' => 3, '%' => 3, '+' => 2, '-' => 2];
    $rightAssoc = ['^' => true, 'u' => true];
    $out = []; $ops = []; $prev = null;
    foreach ($tok as $t) {
        if (is_numeric($t)) { $out[] = (float)$t; $prev = 'num'; continue; }
        if ($t === '(') { $ops[] = $t; $prev = null; continue; }
        if ($t === ')') {
            while ($ops && end($ops) !== '(') $out[] = array_pop($ops);
            if (!$ops) return ['err' => 'Unbalanced parentheses.'];
            array_pop($ops); $prev = 'num'; continue;
        }
        if ($t === '-' && $prev !== 'num') { $ops[] = 'u'; $prev = null; continue; }
        while ($ops && end($ops) !== '(' && ($prec[end($ops)] > $prec[$t]
               || ($prec[end($ops)] === $prec[$t] && empty($rightAssoc[$t])))) {
            $out[] = array_pop($ops);
        }
        $ops[] = $t; $prev = null;
    }
    while ($ops) {
        $op = array_pop($ops);
        if ($op === '(') return ['err' => 'Unbalanced parentheses.'];
        $out[] = $op;
    }

    $st = [];
    foreach ($out as $t) {
        if (is_float($t)) { $st[] = $t; continue; }
        if ($t === 'u') {
            if (!$st) return ['err' => 'Could not read that expression.'];
            $st[] = -array_pop($st); continue;
        }
        if (count($st) < 2) return ['err' => 'Could not read that expression.'];
        $b = array_pop($st); $a = array_pop($st);
        switch ($t) {
            case '+': $st[] = $a + $b; break;
            case '-': $st[] = $a - $b; break;
            case '*': $st[] = $a * $b; break;
            case '/': if ($b == 0.0) return ['err' => 'Division by zero.'];
                      $st[] = $a / $b; break;
            case '%': if ($b == 0.0) return ['err' => 'Division by zero.'];
                      $st[] = fmod($a, $b); break;
            case '^': if (abs($b) > 1000) return ['err' => 'Exponent too large.'];
                      // 0 to a negative power is a division by zero (PHP 8.5
                      // deprecates it; PHP 9 throws)
                      if ($a == 0.0 && $b < 0) return ['err' => 'Division by zero.'];
                      $st[] = $a ** $b; break;
        }
        if (!is_finite(end($st))) return ['err' => 'Result out of range.'];
    }
    if (count($st) !== 1) return ['err' => 'Could not read that expression.'];
    return ['res' => df_num($st[0])];
}

// frankfurter.app occasionally hiccups the same unpredictable way Gutendex and
// dictionaryapi.dev do (see ebook.php's gutendex_get(), define.php's
// define_lookup()) -- retry a few times before giving up, and return null (a
// real fetch failure) distinctly from a valid response that just doesn't
// contain the requested currency code, so calc.php can tell "service down"
// from "not a real currency pair" instead of showing the same message either
// way.
//
// Retry only on a true fetch failure (no response, or a body that isn't even
// JSON -- e.g. a raw Cloudflare HTML error page) -- NOT on HTTP status.
// Confirmed live: an invalid currency pair (e.g. XYZ/ABC) genuinely gets a
// well-formed `{"message":"not found"}` with a 404 from the real API, after
// a 301 redirect that curl follows -- that first version of this fix treated
// any >=400 status as a reason to retry, which meant a real "unknown pair"
// got silently swallowed into three wasted retries and a false "temporarily
// unavailable". A 404 with real JSON is a completed, trustworthy answer; the
// caller already handles "no rates key" as "unknown pair" correctly once it
// actually receives one.
// The currencies Frankfurter (ECB reference rates) actually has, from
// https://api.frankfurter.dev/v1/currencies on 2026-11-12. Checked before any
// API call, so a three-letter unit like "mph" never reaches the currency
// service. Keep in step with that endpoint if the ECB adds or drops one.
// (A function, not a file-level const: this page's code runs before a const
// declared down here would exist.)
function df_currencies(): array {
    return ['AUD', 'BRL', 'CAD', 'CHF', 'CNY', 'CZK', 'DKK', 'EUR', 'GBP', 'HKD',
            'HUF', 'IDR', 'ILS', 'INR', 'ISK', 'JPY', 'KRW', 'MXN', 'MYR', 'NOK', 'NZD', 'PHP', 'PLN',
            'RON', 'SEK', 'SGD', 'THB', 'TRY', 'USD', 'ZAR'];
}

// api.frankfurter.app now 301s to api.frankfurter.dev/v1 (checked 2026-11-12):
// call v1 directly instead of paying for the redirect on every miss.
function df_frankfurter_rates(string $from, string $to): ?array {
    $url = 'https://api.frankfurter.dev/v1/latest?from=' . $from . '&to=' . $to;
    for ($i = 0; $i < 3; $i++) {
        if ($i > 0) usleep(400000);
        $r = http_get_cached($url, 43200, 3000000, '');
        if ($r === null) continue;
        $j = json_decode($r['body'], true);
        if (is_array($j)) return $j;
    }
    return null;
}

// --- conversions --------------------------------------------------------------
function df_convert(float $n, string $fu, string $tu): array {
    $alias = [
        'inch' => 'in', 'inches' => 'in', '"' => 'in', 'foot' => 'ft', 'feet' => 'ft',
        'yard' => 'yd', 'yards' => 'yd', 'mile' => 'mi', 'miles' => 'mi',
        'millimeter' => 'mm', 'centimeter' => 'cm', 'meter' => 'm', 'meters' => 'm',
        'metre' => 'm', 'metres' => 'm', 'kilometer' => 'km', 'kilometers' => 'km', 'kms' => 'km',
        'ounce' => 'oz', 'ounces' => 'oz', 'pound' => 'lb', 'pounds' => 'lb', 'lbs' => 'lb',
        'stone' => 'st', 'gram' => 'g', 'grams' => 'g', 'kilogram' => 'kg', 'kilograms' => 'kg',
        'kilo' => 'kg', 'kilos' => 'kg',
        'teaspoon' => 'tsp', 'tablespoon' => 'tbsp', 'cups' => 'cup', 'pint' => 'pt',
        'pints' => 'pt', 'quart' => 'qt', 'quarts' => 'qt', 'gallon' => 'gal', 'gallons' => 'gal',
        'milliliter' => 'ml', 'liter' => 'l', 'liters' => 'l', 'litre' => 'l', 'litres' => 'l',
        // added 2026-11-12: plurals and spellings that used to fail
        'kilometre' => 'km', 'kilometres' => 'km', 'centimeters' => 'cm', 'centimetre' => 'cm',
        'centimetres' => 'cm', 'millimeters' => 'mm', 'millimetre' => 'mm', 'millimetres' => 'mm',
        'teaspoons' => 'tsp', 'tablespoons' => 'tbsp', 'milliliters' => 'ml', 'millilitres' => 'ml',
        'fl oz' => 'floz', 'fluid ounce' => 'floz', 'fluid ounces' => 'floz',
        'tonne' => 't', 'tonnes' => 't', 'metric ton' => 't', 'ton' => 'ton', 'tons' => 'ton',
        'byte' => 'byte', 'bytes' => 'byte', 'b' => 'byte', 'bit' => 'bit', 'bits' => 'bit',
        'km/h' => 'kmh', 'kph' => 'kmh', 'kmph' => 'kmh', 'm/s' => 'mps', 'knot' => 'kn',
        'knots' => 'kn', 'kt' => 'kn',
        'celsius' => 'c', "\u{00B0}c" => 'c', 'fahrenheit' => 'f', "\u{00B0}f" => 'f', 'kelvin' => 'k',
    ];
    $fu = strtolower(trim(preg_replace('/\s+/', ' ', $fu))); $tu = strtolower(trim(preg_replace('/\s+/', ' ', $tu)));
    $fu = $alias[$fu] ?? $fu;
    $tu = $alias[$tu] ?? $tu;

    // temperature is affine, not linear
    $temps = ['c', 'f', 'k'];
    if (in_array($fu, $temps, true) && in_array($tu, $temps, true)) {
        $c = $fu === 'c' ? $n : ($fu === 'f' ? ($n - 32) / 1.8 : $n - 273.15);
        $r = $tu === 'c' ? $c : ($tu === 'f' ? $c * 1.8 + 32 : $c + 273.15);
        return ['res' => df_num($r) . ' ' . strtoupper($tu === 'k' ? 'K' : "\u{00B0}" . $tu)];
    }

    $tables = [
        'length' => ['in' => .0254, 'ft' => .3048, 'yd' => .9144, 'mi' => 1609.344,
                     'mm' => .001, 'cm' => .01, 'm' => 1, 'km' => 1000],
        'mass'   => ['oz' => .028349523, 'lb' => .45359237, 'st' => 6.35029318,
                     'g' => .001, 'kg' => 1, 't' => 1000, 'ton' => 907.18474],   // ton = US short ton
        'volume' => ['tsp' => .00492892, 'tbsp' => .01478676, 'floz' => .02957353,
                     'cup' => .2365882, 'pt' => .4731765, 'qt' => .9463529,
                     'gal' => 3.785412, 'ml' => .001, 'l' => 1],
        'data'   => ['kb' => 1e3, 'mb' => 1e6, 'gb' => 1e9, 'tb' => 1e12,
                     'kib' => 1024, 'mib' => 1048576, 'gib' => 1073741824,
                     'byte' => 1, 'bit' => .125],
        'speed'  => ['mph' => .44704, 'kmh' => 1 / 3.6, 'mps' => 1, 'kn' => .514444, 'fps' => .3048],
    ];
    $label = ['floz' => 'fl oz', 'kmh' => 'km/h', 'mps' => 'm/s', 'kn' => 'knots', 'fps' => 'ft/s',
              'byte' => 'bytes', 'bit' => 'bits', 'ton' => 'tons (US)'];
    foreach ($tables as $tbl) {
        if (isset($tbl[$fu], $tbl[$tu])) {
            return ['res' => df_num($n * $tbl[$fu] / $tbl[$tu]) . ' ' . ($label[$tu] ?? $tu)];
        }
    }

    // currencies: only codes Frankfurter has (df_currencies()), checked before any
    // API call -- "mph to kph" used to cost an upstream request and come back as
    // "Unknown currency pair" (2026-11-12)
    $F = strtoupper($fu); $T = strtoupper($tu);
    $isCur = function (string $c): bool { return in_array($c, df_currencies(), true); };
    if ($isCur($F) && $isCur($T) && $F === $T) {
        return ['res' => df_num($n) . ' ' . $T, 'note' => 'Same currency.'];
    }
    if (preg_match('/^[a-z]{3}$/', $fu) && preg_match('/^[a-z]{3}$/', $tu)
        && ($isCur($F) xor $isCur($T))) {
        $other = $isCur($F) ? $T : $F;
        return ['err' => $other . ' is not one of the currencies with ECB reference rates ('
                       . implode(' ', df_currencies()) . ').'];
    }
    if ($isCur($F) && $isCur($T)) {
        $j = df_frankfurter_rates($F, $T);
        if ($j === null) {
            return ['err' => 'The currency conversion service is temporarily unavailable. '
                           . 'Please try again shortly.'];
        }
        $rate = $j['rates'][strtoupper($tu)] ?? null;
        if ($rate !== null) {
            return ['res' => df_num($n * (float)$rate) . ' ' . strtoupper($tu),
                    'note' => '1 ' . strtoupper($fu) . ' = ' . df_num((float)$rate) . ' '
                            . strtoupper($tu) . ' (ECB reference rate, ' . ($j['date'] ?? '') . ')'];
        }
        return ['err' => 'Unknown currency pair ' . strtoupper($fu) . '/' . strtoupper($tu) . '.'];
    }
    return ['err' => "Can't convert $fu to $tu. Try length, weight, volume, data, "
                   . 'temperature, or a currency pair.'];
}
