<?php
// DuckFind configuration.
//
//   cp config.example.php config.php   and edit config.php
//
// config.php is git-ignored, so your settings and feed list stay local.
// If config.php is absent, DuckFind falls back to the values below.

return [
    // --- Branding -------------------------------------------------------
    'name'       => 'DuckFind',
    'base_url'   => 'http://duckfind.com',   // your public URL (used in SEO tags + sitemap)
    // Set true on a MIRROR/secondary host so search engines don't index a
    // duplicate copy — only the primary site should rank. Leave false on primary.
    'noindex_all' => false,
    // Many news sites (NPR, etc.) drop obvious bot user-agents at the CDN/WAF,
    // so DuckFind sends a browser UA to fetch the same HTML a browser would get.
    'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',

    // --- Outbound fetching ---------------------------------------------
    'timeout'    => 12,                       // seconds per request
    // Cache directory (must be writable by the web-server user). Holds
    // fetched pages, converted images, and feeds. Safe to delete anytime.
    // Put this on DISK, not a tmpfs — see rate_dir below for why.
    'cache_dir'  => sys_get_temp_dir() . '/duckfind-cache',
    // Total cache size ceiling (bytes). Evicted oldest-first when exceeded, so
    // an attacker sending unique URLs can't fill the disk (a full disk makes the
    // rate limiter fail open). Keep comfortably below the volume's free space.
    'cache_max_bytes' => 8589934592,         // 8 GB
    // Rate-limit + daily-counter state. Defaults to "<cache_dir>/rl". Keep it on
    // a real disk, NOT /tmp: /tmp is often a small tmpfs, and if it fills the
    // file-locked rate limiter fails OPEN — silently disabling every per-IP limit
    // and the daily caps. (Set explicitly only if your cache_dir is a tmpfs.)
    // 'rate_dir'   => '/var/lib/duckfind/rl',

    // --- Download proxy -------------------------------------------------
    // Max file the download proxy will stream. 50 MB covers essentially all
    // real retro software/archives; bigger files aren't realistic on vintage
    // hardware and just burn bandwidth. Raise it if you host large images.
    'dl_max_bytes'  => 52428800,              // 50 MB
    // Long streams (dl.php, ftp.php file downloads, watch.php's raw video) each
    // hold a php-fpm worker for minutes. These cap how many run AT ONCE, so a
    // single client (or a burst of them) can't occupy the whole pool. Keep the
    // global cap well under pm.max_children. Over the cap: 429 per client,
    // 503 site-wide, both with Retry-After.
    'stream_max_per_client' => 2,
    'stream_max_global'     => 4,
    // Site-wide cap on outbound FTP fetches (ftp.php directory listings and
    // file downloads, all visitors combined) per UTC hour. Per-IP limits
    // don't stop a bot spread over many addresses. Over the cap: 503 with
    // Retry-After until the next hour; the daily 'ftpcapped' counter counts
    // refusals. 0 disables the cap.
    'ftp_hourly_cap' => 200,
    // Site-wide cap on uncached OpenStreetMap tile fetches (map.php's GIF
    // stitch, all visitors combined) per UTC hour; OSM's tile policy does not
    // allow bulk fetching. Over the cap a map is still served from cached
    // tiles, with the uncached ones left grey and the map not cached; the
    // daily 'mapcapped' counter counts those maps, and 'maptile' counts the
    // tile fetches made (to size the cap). 0 disables the cap.
    'map_tile_hourly_cap' => 300,
    // Site-wide cap on uncached page fetches by the reader (read.php, live or
    // Wayback, all visitors combined) per UTC hour; cached pages still work.
    // Over the cap: 503 with Retry-After until the next hour; the daily
    // 'readcapped' counter counts refusals. 0 disables the cap.
    'read_hourly_cap' => 300,
    // Site-wide cap on uncached DuckDuckGo fetches (search pages, html and the
    // lite fallback together) per UTC hour, on top of search_daily_cap. Over
    // it: 503 "search busy" with Retry-After; the daily 'searchcapped' counter
    // counts refusals. 0 disables it. (After a DDG block, searches also back
    // off 60 s -> 5 min -> 15 min without contacting DDG; daily 'ddgbackoff'.)
    'search_hourly_cap' => 200,

    // --- Image proxy ----------------------------------------------------
    'img_max_w'     => 480,                   // default downscale width (px)
    'img_max_h'     => 600,
    'img_fetch_cap' => 8000000,               // max source-image bytes
    // ASCII-art image mode (im=ascii): the PAGE fetches images and inlines
    // them as text art, so bound what one page view can cost.
    'ascii_max_per_page' => 8,                // images turned into art per page
    'ascii_time_budget'  => 6,                // seconds for all of a page's image fetches

    // --- Trusted proxies -----------------------------------------------
    // Proxies whose forwarded client-IP headers (CF-Connecting-IP /
    // X-Forwarded-For) we trust for rate limiting. Those headers are spoofable,
    // so leave this EMPTY if DuckFind faces clients directly. If it sits behind
    // Cloudflare / nginx / a tunnel, list that proxy's source address (the value
    // in REMOTE_ADDR), e.g. ['192.168.30.101/32'] or Cloudflare's IP ranges.
    // With more than one proxy hop (e.g. Cloudflare -> nginx), list every hop:
    // X-Forwarded-For is read right to left and the first untrusted address
    // in it is taken as the client.
    'trusted_proxies' => [],

    // --- Privacy statement ----------------------------------------------
    // DuckFind itself never logs searches, but that claim is only honest if
    // the whole host cooperates: no web-server access logs and no logging
    // CDN/proxy in front. Set true ONLY then — it enables the "searches are
    // never logged" footer line and the no-logs promise on about.php.
    'privacy_claims' => false,
    // Set true ONLY if this host actually runs the network-level flood protection
    // from examples/flood-protection.md (temporary escalating bans of abusive
    // addresses). It gates the matching disclosure on about.php, so a self-host
    // without it doesn't claim something untrue.
    'flood_protection' => false,
    // Optional host-specific paragraph on about.php's Privacy section (plain
    // HTML) — e.g. disclose a CDN that can observe traffic in transit.
    'privacy_extra' => '',

    // Site-wide daily cap on NEW searches (cache misses that actually hit
    // DuckDuckGo). Per-IP limits don't stop a botnet, and enough scraped
    // searches could get the server IP blocked by DDG. Cached searches still
    // work once the cap is hit. 0 disables the cap. When the html endpoint
    // fails and index.php falls back to DuckDuckGo Lite, that uncached lite
    // fetch takes a unit too (the cap counts outbound DDG fetches).
    'search_daily_cap' => 5000,

    // Browser-proof cookie gate on cheap pages (lib.php, df_pob_measure). A
    // client with no valid df_pob cookie gets one 302 that sets it; if it still
    // has none it sees a "cookies required" page. Known search crawlers and
    // vintage/minimal browsers (many have no cookie support) are never gated.
    // false = count only, no gate (switch off here without a deploy).
    // The expensive features (reader, images, maps, downloads ...) always
    // require the cookie (df_require_browser_proof), whatever this says; there
    // too, vintage browsers pass without it (counted in daily_pobxlegacy),
    // except on the paid !ai answers.
    'pob_gate' => true,

    // --- Per-IP rate limits: [max_requests, window_seconds] ------------
    'rate' => [
        // Site-wide floor for cheap pages (landing, bang redirects, about, settings,
        // sitemap, guestbook, ...) so a flood of them can't pin the small php-fpm pool
        // while every expensive bucket stays flat. Deliberately generous: a search
        // costs one 'page' + one 'search' hit. Not applied to img.php, map.php's gif
        // tiles, watch.php's status poll, or the error-*.php / busy.php pages (served
        // by the web server mid-failure; counting them adds disk I/O when the box is
        // already overloaded). If config.php lacks this key, df_rate() falls back to 60/60.
        'page'   => [120, 60],
        'search' => [40, 60],
        'read'   => [90, 60],
        'img'    => [200, 60],                 // each is an 8MB fetch + GD decode on 1 vCPU
        'news'   => [60, 60],
        'map'    => [30, 60],
        'pdf'    => [15, 60],                  // spawns a poppler process — heaviest request
        'dl'     => [20, 60],                  // download proxy — streams whole files
        'ftp'    => [20, 60],                  // ftp gateway — same cost shape as dl (listing or file)
        'ai'     => [10, 3600],               // AI answers: 10 per hour per IP
        'watch'  => [40, 300],                 // video relay — generous because the wait page polls itself
                                                // every 10s while a cold transcode runs; the actual expensive
                                                // work (a new transcode job) is bounded by the relay itself,
                                                // not by this counter
        'ytsearch' => [20, 60],                // lightweight -- just a metadata query, no transcoding
        'watchcheck' => [80, 300],             // the wait page's JS poll (every ~3s) -- cheap status check only
    ],

    // --- Video watch (optional) ------------------------------------------
    // The `!watch <youtube url>` shortcut fetches a YouTube video and
    // transcodes it server-side into something a vintage machine can decode
    // (Cinepak/AVI, MPEG-1, or Sorenson/FLV) instead of the VP9/AV1 nothing
    // an old QuickTime or Media Player understands. OFF until relay_url is
    // set — this app does not do the fetch/transcode itself, it just calls a
    // small trusted backend you run yourself (the relay is not part of this
    // repo; watch.php is the client side of it).
    // relay_secret is sent as the X-Relay-Secret header; keep it out of
    // version control (config.php is gitignored) and matching on both ends.
    'relay_url'    => '',                     // e.g. 'https://relay.duckfind.com'
    'relay_secret' => '',

    // --- AI answers (optional, paid) -----------------------------------
    // The `!ai <question>` shortcut answers questions with Claude, rendered as
    // plain HTML. It is OFF until you set an API key here. Get one at
    // https://console.anthropic.com/ — paste it below (starts with "sk-ant-").
    // Haiku is the cheapest model (~$0.0025 per short answer).
    //
    // Two limits keep the bill bounded: the per-IP 'ai' rate above stops one
    // visitor hammering it, and ai_daily_cap is a HARD site-wide ceiling — even
    // a swarm of IPs can't exceed it. Your maximum possible spend per day is
    // roughly ai_daily_cap * $0.0025 (500/day ~= $1.25/day). When the cap is
    // hit, `!ai` says so and falls back to normal search.
    'ai_api_key'    => '',                    // <-- PUT YOUR ANTHROPIC KEY HERE (empty = feature off)
    'ai_model'      => 'claude-haiku-4-5',    // cheapest; or 'claude-sonnet-5' for better answers
    'ai_max_tokens' => 500,                   // caps answer length (and per-answer cost)
    'ai_daily_cap'  => 500,                   // hard site-wide max AI answers per day

    // --- News portal: section => [source label => RSS/Atom feed URL] ---
    'news_sections' => [
        'World' => [
            'BBC'        => 'https://feeds.bbci.co.uk/news/world/rss.xml',
            'NPR'        => 'https://feeds.npr.org/1001/rss.xml',
            'Al Jazeera' => 'https://www.aljazeera.com/xml/rss/all.xml',
        ],
        'Technology' => [
            'Hacker News'  => 'https://news.ycombinator.com/rss',
            'Ars Technica' => 'https://feeds.arstechnica.com/arstechnica/index',
            'The Verge'    => 'https://www.theverge.com/rss/index.xml',
        ],
        'Science' => [
            'Science Daily' => 'https://www.sciencedaily.com/rss/all.xml',
            'Phys.org'      => 'https://phys.org/rss-feed/',
        ],
        'Gaming' => [
            'Rock Paper Shotgun' => 'https://www.rockpapershotgun.com/feed',
            'PC Gamer'           => 'https://www.pcgamer.com/rss/',
        ],
        'Retro & Computing' => [
            'Hackaday' => 'https://hackaday.com/blog/feed/',
            'OSNews'   => 'https://www.osnews.com/feed/',
        ],
    ],
];
