<?php
// DuckFind about page: how the site treats visitors (privacy) and the limits
// it enforces (the "why did I get a 429" page). App-level facts hold for any
// install; the host-level no-logs promise renders only where the operator
// affirmed it in config (privacy_claims), since the app can't verify its own
// server's logging. privacy_extra carries host-specific disclosures.
require __DIR__ . '/lib.php';

header('Content-Type: text/html; charset=iso-8859-1');
echo page_head(DUCKFIND_NAME . ' - about', false,
    'How ' . DUCKFIND_NAME . ' works: a self-hosted proxy that fetches the modern web '
    . 'server-side and serves clean HTML 3.2 to vintage browsers. What it does, its privacy '
    . 'policy, and its limits.');
echo '<form action="/" method="get">' . df_brand_link() . '&nbsp;&nbsp;'
   . '<input type="text" name="q" size="26">&nbsp;<input type="submit" value="Quack!"></form>';

echo '<h2>What is ' . DUCKFIND_NAME . '?</h2>';
echo '<p>' . DUCKFIND_NAME . ' is a search engine and article reader for old computers. '
   . 'The modern web is megabytes of scripts, styles and fonts behind TLS connections a '
   . 'vintage browser cannot even open -- so ' . DUCKFIND_NAME . ' fetches today&#39;s '
   . 'pages on the server and hands your machine clean HTML 3.2: no scripts, no '
   . 'stylesheets, images converted to small GIFs. It renders on anything from a System 7 '
   . 'Mac or a Windows 3.1 box to an Apple II with a text browser.</p>';
echo '<p>Search is powered by DuckDuckGo. Also included:</p>';
echo '<ul>'
   . '<li><a href="/read.php">Wayback reader</a></li>'
   . '<li><a href="/news.php">news portal</a> and <a href="/feeds.php">personal feed reader</a></li>'
   . '<li><a href="/map.php">street maps with directions</a></li>'
   . '<li><a href="/weather.php">weather forecasts</a></li>'
   . '<li><a href="/calc.php">calculator and unit/currency converter</a></li>'
   . '<li><a href="/define.php">dictionary</a></li>'
   . '<li><a href="/pdf.php">PDF viewer</a></li>'
   . '<li><a href="/dl.php">file-download proxy</a></li>'
   . '<li><a href="/hn.php">Hacker News with comment threads</a></li>'
   . '<li><a href="/translate.php">translator</a></li>'
   . '<li><a href="/gopher.php">gopher</a></li>'
   . '<li><a href="/wiby.php">Wiby classic-web search</a></li>'
   . (trim((string)df_cfg('relay_url', '')) !== ''
       ? '<li><a href="/watch.php">YouTube video playback</a></li>' : '')
   . (is_executable(DUCKFIND_YTDLP_BIN)
       ? '<li><a href="/ytsearch.php">YouTube search</a></li>' : '')
   . (trim((string)df_cfg('ai_api_key', '')) !== ''
       ? '<li><a href="/ask.php">AI answers</a> (<tt>!ai</tt>)</li>' : '')
   . '<li>bang shortcuts (try <tt>!help</tt>)</li>'
   . '</ul>';
echo '<p>Inspired by FrogFind (frogfind.com) -- an independent, '
   . 'open-source implementation you can <a href="https://github.com/d4rkwyng/duckfind">run '
   . 'yourself</a>.</p>';

echo '<h2>Privacy</h2>';
echo '<img src="/duck-privacy.gif" alt="' . DUCKFIND_NAME . '" width="200" height="200" align="right" hspace="12" vspace="4">';
// A host that hasn't affirmed the no-logs claims must say who it is NOT:
// visitors shouldn't read the official site's reputation into a mirror or an
// independently hosted copy whose operator's logging we can't vouch for.
if (!df_cfg('privacy_claims', false)) {
    echo '<p><b>About this server:</b> this is not the official '
       . '<a href="http://duckfind.com/">duckfind.com</a> -- it is a mirror or an '
       . 'independently hosted copy of the software (which is encouraged!). Everything '
       . 'below describes what the <i>software</i> does. Whether this server&#39;s '
       . 'operator keeps logs of their own is outside the software&#39;s control, and '
       . 'this server has not affirmed the official site&#39;s no-logs guarantee.'
       . '</p>';
}
echo '<p>Searches and pages are fetched by the server on your behalf, '
   . 'so websites and search engines see ' . DUCKFIND_NAME . '&#39;s address, not yours. '
   . 'Fetched pages and images live briefly in a server cache keyed by URL -- never '
   . 'by visitor -- and expire within days. Rate limiting stores a salted hash of '
   . 'your address, never the address itself.</p>';
echo '<p>The one exception: <a href="/feeds.php">My Feeds</a> saves your feed list '
   . 'under a salted hash of your reader code, and it persists as long as you '
   . 'revisit it at least once every ~400 days -- everything else above expires '
   . 'within days.</p>';
if (trim((string)df_cfg('ai_api_key', '')) !== '') {
    echo '<p>The optional <tt>!ai</tt> shortcut sends that question -- and nothing '
       . 'else -- to Anthropic to generate the answer.</p>';
}
if (trim((string)df_cfg('relay_url', '')) !== '') {
    echo '<p>The optional <tt>!watch</tt> shortcut is handled by a separate server '
       . '(reached over Cloudflare) that fetches and converts video for old machines -- '
       . 'unlike the rest of ' . DUCKFIND_NAME . ', that path is not guaranteed log-free: '
       . 'it keeps no access logs of its own, but Cloudflare sits in between and may log '
       . 'traffic through it. (<tt>!ytsearch</tt> is unrelated -- it runs a metadata-only '
       . 'search locally on this server, no relay hop.)</p>';
}
if (df_cfg('privacy_claims', false)) {
    echo '<p><b>This site keeps no logs of what you search or read</b> '
       . '-- no web-server access logs, and no logging proxy or CDN in front.</p>';
}
echo '<br clear="right">';
echo '<p>One inherent limit: vintage browsers speak plain HTTP, so the '
   . 'networks between you and this server can observe that traffic in transit -- '
   . 'the price of working on old machines. A modern browser can use the encrypted '
   . '<tt>https://</tt> address instead.</p>';
if (trim((string)df_cfg('privacy_extra', '')) !== '') {
    echo '<p>' . df_cfg('privacy_extra', '') . '</p>';
}

echo '<h2>Limits</h2>';
echo '<img src="/duck-limits.gif" alt="' . DUCKFIND_NAME . '" width="200" height="200" align="left" hspace="12" vspace="4">';
echo '<p>Limits keep ' . DUCKFIND_NAME . ' available for everyone '
   . '(and keep its search backend happy). Per visitor:</p>';
$aiOn    = trim((string)df_cfg('ai_api_key', '')) !== '';
$watchOn = trim((string)df_cfg('relay_url', '')) !== '';
// !ytsearch is independent of the relay -- it runs local yt-dlp and works
// (or doesn't) whether or not !watch/relay_url is configured. Gating its
// bucket on $watchOn would show/hide the "video searches" limit backwards
// from what's actually enforced (see ytsearch.php, which never even calls
// df_rate('ytsearch') when yt-dlp isn't present, regardless of relay_url).
$ytsearchOn = is_executable(DUCKFIND_YTDLP_BIN);
$labels  = ['search' => 'searches', 'read' => 'article reads', 'img' => 'images',
            'news' => 'news pages', 'ai' => 'AI answers', 'watch' => 'video conversions',
            'ytsearch' => 'video searches', 'watchcheck' => 'video status checks'];
echo '<ul>';
foreach (df_cfg('rate', []) as $bucket => $r) {
    if (!is_array($r) || count($r) < 2) continue;
    if ($bucket === 'ai' && !$aiOn) continue;
    if (($bucket === 'watch' || $bucket === 'watchcheck') && !$watchOn) continue;
    if ($bucket === 'ytsearch' && !$ytsearchOn) continue;
    $what = $labels[$bucket] ?? $bucket;
    $secs = (int)$r[1];
    $win  = $secs === 60 ? 'minute' : ($secs === 3600 ? 'hour'
          : ($secs % 60 === 0 ? ($secs / 60) . ' minutes' : $secs . ' seconds'));
    echo '<li>' . (int)$r[0] . ' ' . $what . ' per ' . $win . '</li>';
}
echo '</ul>';
$scap = (int)df_cfg('search_daily_cap', 5000);
$acap = (int)df_cfg('ai_daily_cap', 500);
$site = [];
if ($scap > 0)          $site[] = $scap . ' new searches';
if ($aiOn && $acap > 0) $site[] = $acap . ' AI answers';
if ($site) {
    echo '<p>Shared by all visitors: a daily budget of '
       . implode(' and ', $site) . '. When it runs out, recently searched terms keep '
       . 'working from cache and everything resets at midnight UTC.</p>';
}
echo '<p>Fetches are capped in size and time, so very large pages and '
   . 'images arrive trimmed rather than not at all. The download proxy accepts files up to '
   . (int)((int)df_cfg('dl_max_bytes', 52428800) / 1048576) . ' MB.</p>';
echo '<br clear="left">';

echo '<h2>Meet Mallard</h2>';
echo '<img src="/duck-mallard.gif" alt="Mallard" width="200" height="199" align="right" hspace="12" vspace="4">';
echo '<p>Mallard is ' . DUCKFIND_NAME . '&#39;s detective duck -- he does the legwork of '
   . 'fetching, stripping, and converting the modern web so your old browser never has to '
   . 'deal with it directly.</p>';
echo '<br clear="right">';

echo page_foot();
