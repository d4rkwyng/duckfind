<?php
require __DIR__ . '/lib.php';
http_response_code(504);
header('Content-Type: text/html; charset=iso-8859-1');
echo page_head(DUCKFIND_NAME . ' - taking too long', true);
echo '<center><img src="/duck-504.gif" alt="' . DUCKFIND_NAME . '" width="240" height="240"></center>';
echo '<h1>This duck got tired of waiting.</h1>';
echo '<p>That took longer than expected. Try again in a moment.</p>';
echo page_foot();
