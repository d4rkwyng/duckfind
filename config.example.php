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

    // --- Per-IP rate limits: [max_requests, window_seconds] ------------
    'rate' => [
        'search' => [40, 60],
        'read'   => [90, 60],
        'img'    => [400, 60],
        'news'   => [60, 60],
    ],

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
