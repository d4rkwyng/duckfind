<?php
// DuckFind calculator & unit converter — server-side math for machines whose
// calculator desk accessory predates the euro. Two input shapes, auto-detected:
//   "2 + 2 * (14 - 3) ^ 2"       arithmetic (own shunting-yard parser, no eval)
//   "5 mi to km" / "72 f to c"   unit conversion, plus live currency
//   "100 usd to jpy"             via frankfurter.app (ECB rates, cached 12 h)
require __DIR__ . '/lib.php';

if (!df_rate('search')) df_rate_block();
header('Content-Type: text/html; charset=iso-8859-1');

$q = trim(df_input('q'));

echo page_head(DUCKFIND_NAME . ' - calculator' . ($q !== '' ? ' - ' . $q : ''));
echo '<form action="/calc.php" method="get"><a href="/"><b>' . DUCKFIND_NAME . '</b></a>&nbsp;&nbsp;'
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

if (preg_match('/^(-?[\d.,]+)\s*([a-z\x{00B0}]+)\s+(?:to|in)\s+([a-z\x{00B0}]+)$/iu', $q, $m)) {
    $out = df_convert((float)str_replace(',', '', $m[1]), $m[2], $m[3]);
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
    $s = rtrim(rtrim(sprintf('%.8G', $n), '0'), '.');
    return $s === '' || $s === '-' ? '0' : $s;
}

// --- arithmetic: tokenize + shunting-yard + RPN eval. No eval(), ever. -------
function df_calc(string $expr): array {
    if (!preg_match('/^[\d\s+\-*\/%^().,x]+$/i', $expr)) {
        return ['err' => 'Only numbers and + - * / % ^ ( ) are supported.'];
    }
    $expr = str_ireplace(['x', ','], ['*', ''], $expr);
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
                      $st[] = $a ** $b; break;
        }
        if (!is_finite(end($st))) return ['err' => 'Result out of range.'];
    }
    if (count($st) !== 1) return ['err' => 'Could not read that expression.'];
    return ['res' => df_num($st[0])];
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
        'celsius' => 'c', "\u{00B0}c" => 'c', 'fahrenheit' => 'f', "\u{00B0}f" => 'f', 'kelvin' => 'k',
    ];
    $fu = strtolower($fu); $tu = strtolower($tu);
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
                     'g' => .001, 'kg' => 1, 't' => 1000],
        'volume' => ['tsp' => .00492892, 'tbsp' => .01478676, 'floz' => .02957353,
                     'cup' => .2365882, 'pt' => .4731765, 'qt' => .9463529,
                     'gal' => 3.785412, 'ml' => .001, 'l' => 1],
        'data'   => ['kb' => 1e3, 'mb' => 1e6, 'gb' => 1e9, 'tb' => 1e12,
                     'kib' => 1024, 'mib' => 1048576, 'gib' => 1073741824],
    ];
    foreach ($tables as $tbl) {
        if (isset($tbl[$fu], $tbl[$tu])) {
            return ['res' => df_num($n * $tbl[$fu] / $tbl[$tu]) . ' ' . $tu];
        }
    }

    // three-letter codes that aren't units: try currency (ECB via frankfurter)
    if (preg_match('/^[a-z]{3}$/', $fu) && preg_match('/^[a-z]{3}$/', $tu)) {
        $r = http_get_cached('https://api.frankfurter.app/latest?from=' . strtoupper($fu)
            . '&to=' . strtoupper($tu), 43200);
        $j = $r ? json_decode($r['body'], true) : null;
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
