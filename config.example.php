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
    'base_url'   => 'http://duckfind.com',   // your public URL
    // Many news sites (NPR, etc.) drop obvious bot user-agents at the CDN/WAF,
    // so DuckFind sends a browser UA to fetch the same HTML a browser would get.
    'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',

    // --- Outbound fetching ---------------------------------------------
    'timeout'    => 12,                       // seconds per request
    // Cache directory (must be writable by the web-server user). Holds
    // fetched pages, converted images, and feeds. Safe to delete anytime.
    'cache_dir'  => sys_get_temp_dir() . '/duckfind-cache',

    // --- Image proxy ----------------------------------------------------
    'img_max_w'     => 480,                   // default downscale width (px)
    'img_max_h'     => 600,
    'img_fetch_cap' => 8000000,               // max source-image bytes

    // --- Trusted proxies -----------------------------------------------
    // Proxies whose forwarded client-IP headers (CF-Connecting-IP /
    // X-Forwarded-For) we trust for rate limiting. Those headers are spoofable,
    // so leave this EMPTY if DuckFind faces clients directly. If it sits behind
    // Cloudflare / nginx / a tunnel, list that proxy's source address (the value
    // in REMOTE_ADDR), e.g. ['192.168.30.101/32'] or Cloudflare's IP ranges.
    'trusted_proxies' => [],

    // --- Privacy statement ----------------------------------------------
    // DuckFind itself never logs searches, but that claim is only honest if
    // the whole host cooperates: no web-server access logs and no logging
    // CDN/proxy in front. Set true ONLY then — it enables the "searches are
    // never logged" footer line and the no-logs promise on about.php.
    'privacy_claims' => false,
    // Optional host-specific paragraph on about.php's Privacy section (plain
    // HTML) — e.g. disclose a CDN that can observe traffic in transit.
    'privacy_extra' => '',

    // Site-wide daily cap on NEW searches (cache misses that actually hit
    // DuckDuckGo). Per-IP limits don't stop a botnet, and enough scraped
    // searches could get the server IP blocked by DDG. Cached searches still
    // work once the cap is hit. 0 disables the cap.
    'search_daily_cap' => 5000,

    // --- Per-IP rate limits: [max_requests, window_seconds] ------------
    'rate' => [
        'search' => [40, 60],
        'read'   => [90, 60],
        'img'    => [200, 60],                 // each is an 8MB fetch + GD decode on 1 vCPU
        'news'   => [60, 60],
        'map'    => [30, 60],
        'pdf'    => [15, 60],                  // spawns a poppler process — heaviest request
        'dl'     => [20, 60],                  // download proxy — streams whole files
        'ai'     => [10, 3600],               // AI answers: 10 per hour per IP
    ],

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
