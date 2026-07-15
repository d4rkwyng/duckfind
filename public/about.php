<?php
// DuckFind about page: how the site treats visitors (privacy) and the limits
// it enforces (the "why did I get a 429" page). App-level facts hold for any
// install; the host-level no-logs promise renders only where the operator
// affirmed it in config (privacy_claims), since the app can't verify its own
// server's logging. privacy_extra carries host-specific disclosures.
require __DIR__ . '/lib.php';

header('Content-Type: text/html; charset=iso-8859-1');
echo page_head(DUCKFIND_NAME . ' - about');
echo '<form action="/" method="get"><a href="/"><b>' . DUCKFIND_NAME . '</b></a>&nbsp;&nbsp;'
   . '<input type="text" name="q" size="26">&nbsp;<input type="submit" value="Quack!"></form>';

echo '<h2>What is ' . DUCKFIND_NAME . '?</h2>';
echo '<p><font size="1">' . DUCKFIND_NAME . ' is a search engine and article reader for '
   . 'old computers. The modern web is megabytes of scripts, styles and fonts behind '
   . 'TLS connections a vintage browser cannot even open &mdash; so ' . DUCKFIND_NAME
   . ' fetches today&#39;s pages on the server and hands your machine clean HTML 3.2: '
   . 'no scripts, no stylesheets, images converted to small GIFs. It renders on '
   . 'anything from a System 7 Mac or a Windows 3.1 box to an Apple II with a text '
   . 'browser. Search is powered by DuckDuckGo; the Wayback reader, news portal and '
   . 'bang shortcuts (try <tt>!help</tt>) come along for the ride. Inspired by '
   . '<a href="http://frogfind.com/">FrogFind</a> &mdash; an independent, open-source '
   . 'implementation you can <a href="https://github.com/d4rkwyng/duckfind">run '
   . 'yourself</a>.</font></p>';

echo '<h2>Privacy</h2>';
echo '<p><font size="1">Searches and pages are fetched by the server on your behalf, '
   . 'so websites and search engines see ' . DUCKFIND_NAME . '&#39;s address, not yours. '
   . 'Fetched pages and images live briefly in a server cache keyed by URL &mdash; never '
   . 'by visitor &mdash; and expire within days. Rate limiting stores a salted hash of '
   . 'your address, never the address itself.'
   . (trim((string)df_cfg('ai_api_key', '')) !== ''
       ? ' The optional <tt>!ai</tt> shortcut sends that question &mdash; and nothing '
       . 'else &mdash; to Anthropic to generate the answer.'
       : '')
   . '</font></p>';
if (df_cfg('privacy_claims', false)) {
    echo '<p><font size="1"><b>This site keeps no logs of what you search or read</b> '
       . '&mdash; no web-server access logs, and no logging proxy or CDN in front.</font></p>';
}
if (trim((string)df_cfg('privacy_extra', '')) !== '') {
    echo '<p><font size="1">' . df_cfg('privacy_extra', '') . '</font></p>';
}

echo '<h2>Limits</h2>';
echo '<p><font size="1">Limits keep ' . DUCKFIND_NAME . ' available for everyone '
   . '(and keep its search backend happy). Per visitor:</font></p>';
$aiOn   = trim((string)df_cfg('ai_api_key', '')) !== '';
$labels = ['search' => 'searches', 'read' => 'article reads', 'img' => 'images',
           'news' => 'news pages', 'ai' => 'AI answers'];
echo '<ul><font size="1">';
foreach (df_cfg('rate', []) as $bucket => $r) {
    if (!is_array($r) || count($r) < 2) continue;
    if ($bucket === 'ai' && !$aiOn) continue;
    $what = $labels[$bucket] ?? $bucket;
    $win  = (int)$r[1] === 60 ? 'minute' : ((int)$r[1] === 3600 ? 'hour' : (int)$r[1] . ' seconds');
    echo '<li>' . (int)$r[0] . ' ' . $what . ' per ' . $win . '</li>';
}
echo '</font></ul>';
$scap = (int)df_cfg('search_daily_cap', 5000);
$acap = (int)df_cfg('ai_daily_cap', 500);
$site = [];
if ($scap > 0)          $site[] = $scap . ' new searches';
if ($aiOn && $acap > 0) $site[] = $acap . ' AI answers';
if ($site) {
    echo '<p><font size="1">Shared by all visitors: a daily budget of '
       . implode(' and ', $site) . '. When it runs out, recently searched terms keep '
       . 'working from cache and everything resets at midnight UTC.</font></p>';
}
echo '<p><font size="1">Fetches are capped in size and time, so very large pages and '
   . 'images arrive trimmed rather than not at all.</font></p>';

echo page_foot();
