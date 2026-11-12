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

// df_calc, df_convert and their helpers live in lib.php since 2026-11-12, so the
// search box can answer sums and conversions without a paid search (index.php).
