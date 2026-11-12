<?php
// DuckFind about page: how the site treats visitors (privacy) and the limits
// it enforces (the "why did I get a 429" page). App-level facts hold for any
// install; the host-level no-logs promise renders only where the operator
// affirmed it in config (privacy_claims), since the app can't verify its own
// server's logging. privacy_extra carries host-specific disclosures.
require __DIR__ . '/lib.php';

// Cheap page, but still PHP: counted in the site-wide 'page' bucket (config.example.php).
if (!df_rate('page')) df_rate_block();

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
$braveNote = '(it sees the search terms coming from ' . DUCKFIND_NAME . ' -- never your address -- '
           . 'and the results are not stored here)';
if (df_search_primary() === 'brave') {
    echo '<p>Search is powered by the Brave Search API ' . $braveNote
       . (df_ddg_enabled() ? ', with DuckDuckGo as a fallback when Brave is not answering' : '')
       . '. Also included:</p>';
} else {
    echo '<p>Search is powered by DuckDuckGo'
       . (df_brave_enabled() ? '. When DuckDuckGo is not answering, searches go to the Brave Search API instead ' . $braveNote : '')
       . '. Also included:</p>';
}
echo '<ul>'
   . '<li><a href="/read.php">article reader</a> (with Wayback Machine years)</li>'
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
   . '<li><a href="/ftp.php">anonymous FTP browser/downloader</a></li>'
   . '<li><a href="/wiki.php">Wikipedia lookup</a></li>'
   . '<li><a href="/ebook.php">Project Gutenberg ebook reader</a></li>'
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
   . 'by visitor -- and are deleted within a month at most. Rate limiting stores a salted hash of '
   . 'your address, never the address itself.</p>';
echo '<p>Cookies: a browser-check cookie (it proves a real browser loaded a page, nothing '
   . 'more, and expires after an hour)' . (df_captcha_enabled() ? '; a picture-check pass, '
   . 'only if you solve one, also good for an hour' : '') . '; and your display settings '
   . 'if you change them. None of them says who you are or what you read. My Feeds adds '
   . 'its reader code, below.</p>';
echo '<p>The one exception: <a href="/feeds.php">My Feeds</a> saves your feed list '
   . 'under a salted hash of your reader code, and it persists as long as you '
   . 'revisit it at least once every ~400 days -- everything else above is deleted '
   . 'within a month.</p>';
if (trim((string)df_cfg('ai_api_key', '')) !== '') {
    echo '<p>The optional <tt>!ai</tt> shortcut sends that question -- and nothing '
       . 'else -- to Anthropic to generate the answer.</p>';
}
if (df_render_enabled()) {
    // Derek's approved wording (2026-11-12, via HK-47, msg 1570486134503505932)
    echo '<p>Pages that need JavaScript may be rendered by ' . DUCKFIND_NAME . '&#39;s own '
       . 'server-side browser. The page address passes through Cloudflare on the way.</p>';
}
if (trim((string)df_cfg('relay_url', '')) !== '') {
    echo '<p>The optional <tt>!watch</tt> shortcut\'s video is fetched and converted for '
       . 'old machines by a separate server behind Cloudflare. ' . DUCKFIND_NAME . '\'s server '
       . 'makes that request on your behalf, so Cloudflare sees only which video was '
       . 'requested, coming from ' . DUCKFIND_NAME . ' -- never your IP. (<tt>!ytsearch</tt> is unrelated -- it runs a metadata-only '
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
if (df_cfg('flood_protection', false)) {
    echo '<p>Abusive addresses -- for example, one opening a flood of connections -- may '
       . 'be temporarily blocked at the firewall: for an hour, longer for repeat '
       . 'offenders, up to 7 days at a time. Only the offending address is held, only '
       . 'for the length of the block, and nothing is logged; normal visitors are never '
       . 'recorded.</p>';
}
if (trim((string)df_cfg('privacy_extra', '')) !== '') {
    echo '<p>' . df_cfg('privacy_extra', '') . '</p>';
}

echo '<h2>Limits</h2>';
echo '<img src="/duck-limits.gif" alt="' . DUCKFIND_NAME . '" width="200" height="200" align="left" hspace="12" vspace="4">';
echo '<p>Limits keep ' . DUCKFIND_NAME . ' available for everyone, and keep the sites and '
   . 'services it talks to happy.</p>';
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
            'ytsearch' => 'video searches', 'watchcheck' => 'video status checks',
            'map' => 'map requests', 'pdf' => 'PDF requests', 'dl' => 'downloads',
            'ftp' => 'FTP listings or downloads', 'page' => 'page views'];
// 1. Per visitor (rate buckets), shown in two columns so the list stays short.
$per = [];
foreach (df_cfg('rate', []) as $bucket => $r) {
    if (!is_array($r) || count($r) < 2) continue;
    if ($bucket === 'captcha') continue;               // internal: bounds captcha guessing
    if ($bucket === 'ai' && !$aiOn) continue;
    if (($bucket === 'watch' || $bucket === 'watchcheck') && !$watchOn) continue;
    if ($bucket === 'ytsearch' && !$ytsearchOn) continue;
    $what = $labels[$bucket] ?? $bucket;
    $secs = (int)$r[1];
    $win  = $secs === 60 ? 'minute' : ($secs === 3600 ? 'hour'
          : ($secs % 60 === 0 ? ($secs / 60) . ' minutes' : $secs . ' seconds'));
    $per[] = (int)$r[0] . ' ' . $what . ' per ' . $win;
}
if ($per) {
    echo '<p><b>For each visitor</b></p>';
    $half = (int)ceil(count($per) / 2);
    $cols = [array_slice($per, 0, $half), array_slice($per, $half)];
    echo '<table border="0" cellpadding="2" cellspacing="0"><tr>';
    foreach ($cols as $col) {
        echo '<td valign="top"><ul>';
        foreach ($col as $line) echo '<li>' . $line . '</li>';
        echo '</ul></td>';
    }
    echo '</tr></table>';
}
// 2. Shared by everyone, per hour: the site-wide budgets (lib.php). Only cache
// misses count -- anything someone fetched recently is served from the cache.
$hourly = [];
$hc = (int)df_cfg('search_hourly_cap', 200);
if ($hc > 0) $hourly[] = $hc . ' new searches';
$hc = (int)df_cfg('read_hourly_cap', 300);
if ($hc > 0) $hourly[] = $hc . ' new article fetches';
$hc = (int)df_cfg('map_tile_hourly_cap', 300);
if ($hc > 0) $hourly[] = $hc . ' new map tiles from OpenStreetMap';
if (df_render_enabled() && ($hc = (int)df_cfg('render_hourly_cap', 60)) > 0) {
    $hourly[] = $hc . ' JavaScript page renders';
}
$fcap = (int)df_cfg('ftp_hourly_cap', 200);
if ($fcap > 0) $hourly[] = $fcap . ' FTP fetches (directory listings or files)';
if ($hourly) {
    echo '<p><b>Shared by everyone, per hour</b> (only new fetches count; anything '
       . 'fetched recently comes from the cache):</p><ul>';
    foreach ($hourly as $line) echo '<li>' . $line . '</li>';
    echo '</ul>';
    $tok = (int)df_cfg('read_token_hourly_mult', 3) > 0 && (int)df_cfg('read_hourly_cap', 300) > 0;
    echo '<p>When one of these runs out, '
       . (df_captcha_enabled()
          ? 'you&#39;ll see a quick picture check: type the letters and you&#39;re through for '
            . 'an hour (text-only browsers can&#39;t show the picture, so they wait for the '
            . 'top of the hour). '
          : 'that feature pauses until the top of the hour. ')
       . ($tok ? 'Pages you open from ' . DUCKFIND_NAME . '&#39;s own search results, news '
                 . 'and feeds don&#39;t count against the article budget. ' : '')
       . 'Everything resets on the hour.</p>';
}
// 3. Shared by everyone, per day.
$scap = (int)df_cfg('search_daily_cap', 5000);
$acap = (int)df_cfg('ai_daily_cap', 500);
$site = [];
if ($scap > 0)          $site[] = $scap . ' outbound searches (cache misses sent to ' . df_search_engine_name() . ')';
if ($aiOn && $acap > 0) $site[] = $acap . ' AI answers';
if ($site) {
    echo '<p><b>Shared by everyone, per day:</b> '
       . implode(' and ', $site) . '. When it runs out, recently searched terms keep '
       . 'working from cache and everything resets at midnight UTC.</p>';
}
echo '<p><b>Sizes:</b> fetches are capped in size and time, so very large pages and '
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
