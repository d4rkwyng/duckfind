<?php
require __DIR__ . '/lib.php';
http_response_code(404);
header('Content-Type: text/html; charset=iso-8859-1');
echo page_head(DUCKFIND_NAME . ' - page not gone astray', true);
echo '<center><img src="/duck-404.gif" alt="' . DUCKFIND_NAME . '" width="240" height="240"></center>';
echo '<h1>This duck could not find that.</h1>';
echo '<p>Whatever you were looking for is not here. Double-check the address, or head back and try again.</p>';
echo page_foot();
