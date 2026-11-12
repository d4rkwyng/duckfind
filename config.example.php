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
    // Long reader articles are split into parts of about this many bytes
    // ("Page 2 of 5"), for low-RAM vintage machines. 0 = never split.
    'read_page_bytes' => 32768,
    // Signed reader links (search results, news, HN, feeds) skip the hourly
    // read cap, up to this many times read_hourly_cap per hour site-wide
    // (then the normal cap/captcha applies). 0 = no bypass. Daily counter
    // 'readtokbypass'.
    'read_token_hourly_mult' => 3,
    // Site-wide cap on uncached DuckDuckGo fetches (search pages, html and the
    // lite fallback together) per UTC hour, on top of search_daily_cap. Over
    // it: 503 "search busy" with Retry-After; the daily 'searchcapped' counter
    // counts refusals. 0 disables it. (Separately, a DDG endpoint -- html,
    // lite, translate -- that answers with a block is left alone for 60 s ->
    // 5 min -> 15 min; html backing off falls back to lite. Daily 'ddgbackoff'
    // counts searches refused with both backing off.)
    'search_hourly_cap' => 200,
    // Over one of the hourly caps above (search, reader, FTP, map tiles), show
    // a self-hosted image captcha instead of the plain busy page; solving it
    // sets a signed 1-hour cookie worth captcha_token_budget cap-exempt
    // fetches per hour (per token, never per IP). Daily counters: capshown,
    // capsolved, capfailed, capspent. false keeps the plain busy pages.
    'captcha_enabled'      => true,
    'captcha_token_budget' => 30,
    // Hard ceiling on token-funded units per hour, per capped feature: tokens
    // may add (mult - 1) x that feature's hourly cap (default 2 = the cap
    // again), then everyone gets the plain busy page. Limits an OCR-solving
    // swarm. Daily counters cap<feature>ceiling. 1 = tokens add nothing.
    'captcha_ceiling_mult' => 2,
    // Search fallback when DuckDuckGo gives no usable answer: the Brave Search
    // API ($5 per 1,000 requests, $5 of credit a month). Put the key in the
    // server's config only, never commit it; empty = fallback off. Its own
    // daily cap bounds the bill (100/day = about 3,000/month); results are not
    // cached (Brave's terms allow transient storage only). Daily 'brave'
    // counts requests.
    'brave_api_key'   => '',
    'brave_daily_cap' => 100,
    // Which backend a search asks first: 'brave' (default; needs the key
    // above, else DDG is used) or 'ddg'. The other one is the fallback.
    // ddg_enabled => false switches DuckDuckGo search off entirely (only
    // while Brave is configured, so search always has a backend).
    'search_primary'  => 'brave',
    'ddg_enabled'     => true,

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
        'captcha' => [20, 60],                 // captcha picture + answers: bounds guessing
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
    // Reader fallback for pages built by JavaScript: a headless-Chromium
    // render service (services/render/ in this repo), reached like the relay
    // above and with the same secret. '' = off. Used only for live pages whose
    // own HTML extracts to fewer than render_min_text characters; hourly cap
    // render_hourly_cap; rendered pages cached 30 min. render_ua_mode:
    // 'chrome' (a normal desktop Chrome UA) or 'honest' (adds DuckFind-render).
    'render_url'        => '',                // e.g. 'https://relay.duckfind.com'
    'render_hourly_cap' => 60,
    // render_ask_hourly_cap: "load it through the renderer" clicks on blocked
    // pages (read.php render=1, signed links only), counted separately so they
    // can't starve the automatic fallback; also within render_hourly_cap.
    'render_ask_hourly_cap' => 20,
    'render_min_text'   => 400,
    'render_ua_mode'    => 'chrome',

    // Sites whose bot walls nothing gets past: the reader doesn't fetch them,
    // it says so and offers the Wayback copy. Unset = the built-in list in
    // read.php (rd_walled_default: Reuters, AP, IMDb, eBay, Medium, and
    // People Inc sites such as AllRecipes). A list here replaces it; a host
    // also covers its subdomains. [] = fetch everything.
    // 'read_walled_hosts' => ['reuters.com', 'apnews.com'],

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
    // News page settings (news.php):
    //  - news_budget_seconds: total fetch time per cold page view (each feed
    //    gets at most 5 s); feeds past it come from cached copies.
    //  - feed_hourly_cap: site-wide uncached feed fetches per hour (news and
    //    My Feeds together; over it, cached copies). Daily 'feedcapped'.
    //  - news_favicons: the source's site icon (or the duck) as the picture for
    //    headlines without an image (fav.php).
    'news_budget_seconds' => 10,
    'feed_hourly_cap'     => 200,
    'news_favicons'       => true,
    // Top stories box (above the sections): stories several sources cover, or
    // high on a ranked feed (news_rank_sources: the HN front page is in rank
    // order). news_top_max 0 hides it. news_section_counts: items per section
    // (default 10).
    'news_top_max' => 6,
    'news_rank_sources' => ['Hacker News'],
    'news_section_counts' => ['Technology' => 15],
    // Each section shows 10 headlines, newest first, at most 3 from any one
    // source. Feeds checked working 2026-11-12. RSS 2.0, RSS 1.0/RDF and Atom
    // are all read.
    'news_sections' => [
        'World' => [
            'BBC'          => 'https://feeds.bbci.co.uk/news/world/rss.xml',
            'NPR'          => 'https://feeds.npr.org/1004/rss.xml',
            'The Guardian' => 'https://www.theguardian.com/world/rss',
            'DW'           => 'https://rss.dw.com/xml/rss-en-world',
            'CBC'          => 'https://www.cbc.ca/webfeed/rss/rss-world',
        ],
        'Technology' => [
            'Hacker News'  => 'https://news.ycombinator.com/rss',
            'Ars Technica' => 'https://feeds.arstechnica.com/arstechnica/index',
            'The Register' => 'https://www.theregister.com/headlines.atom',
            'Lobsters'     => 'https://lobste.rs/rss',
            'LWN'          => 'https://lwn.net/headlines/rss',
            'MacRumors'    => 'https://feeds.macrumors.com/MacRumors-All',
            'The Verge' => 'https://www.theverge.com/rss/index.xml',
            'BleepingComputer' => 'https://www.bleepingcomputer.com/feed/',
        ],
        'Retro & Computing' => [
            'Hackaday Retro'    => 'https://hackaday.com/category/retrocomputing/feed/',
            'Retro Dodo' => 'https://retrododo.com/rss/',
            'RetroRGB' => 'https://retrorgb.com/feed',
            'The Digital Antiquarian' => 'https://www.filfre.net/feed/',
            'Tedium' => 'https://feed.tedium.co/',
            'VCF'               => 'https://vcfed.org/feed/',
            'The Old VCR'       => 'https://oldvcr.blogspot.com/feeds/posts/summary?max-results=10',
            'Ken Shirriff'      => 'https://www.righto.com/feeds/posts/summary?max-results=10',
            'The Old New Thing' => 'https://devblogs.microsoft.com/oldnewthing/feed/',
            'Lobsters retro'    => 'https://lobste.rs/t/retrocomputing.rss',
        ],
        'Science' => [
            'NASA'          => 'https://www.nasa.gov/news-release/feed/',
            'Quanta'        => 'https://www.quantamagazine.org/feed/',
            'BBC Science' => 'https://feeds.bbci.co.uk/news/science_and_environment/rss.xml',
            'Nature' => 'https://www.nature.com/nature.rss',
            'Science Daily' => 'https://www.sciencedaily.com/rss/all.xml',
            'NPR Science' => 'https://feeds.npr.org/1007/rss.xml',
        ],
        'Gaming' => [
            'Rock Paper Shotgun' => 'https://www.rockpapershotgun.com/feed',
            'Polygon' => 'https://www.polygon.com/feed/',
            'Eurogamer'          => 'https://www.eurogamer.net/feed',
        ],
        'Sports' => [
            'BBC Sport'    => 'https://feeds.bbci.co.uk/sport/rss.xml',
            'The Guardian' => 'https://www.theguardian.com/sport/rss',
            'CBS Sports'   => 'https://www.cbssports.com/rss/headlines/',
        ],
        'Business' => [
            'BBC'         => 'https://feeds.bbci.co.uk/news/business/rss.xml',
            'NPR'         => 'https://feeds.npr.org/1006/rss.xml',
            'CNBC' => 'https://www.cnbc.com/id/100003114/device/rss/rss.html',
            'The Guardian' => 'https://www.theguardian.com/business/rss',
        ],
    ],
];
