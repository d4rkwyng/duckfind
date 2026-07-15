<?php
// Minimal sitemap for the indexable landing pages (the fetch/tool endpoints are
// disallowed in robots.txt). Generated from base_url so a self-host is correct.
require __DIR__ . '/lib.php';
header('Content-Type: application/xml; charset=UTF-8');
$base = rtrim((string)df_cfg('base_url', 'http://duckfind.com'), '/');
$pages = ['/', '/about.php', '/settings.php'];
echo '<?xml version="1.0" encoding="UTF-8"?>' . "\n";
echo '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' . "\n";
foreach ($pages as $p) {
    echo '  <url><loc>' . htmlspecialchars($base . $p, ENT_XML1) . '</loc>'
       . '<changefreq>weekly</changefreq></url>' . "\n";
}
echo '</urlset>' . "\n";
