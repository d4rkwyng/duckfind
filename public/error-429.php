<?php
require __DIR__ . '/lib.php';
http_response_code(429);
header('Content-Type: text/html; charset=iso-8859-1');
echo page_head(DUCKFIND_NAME . ' - slow down', true);
echo '<center><img src="/duck-429.gif" alt="' . DUCKFIND_NAME . '" width="240" height="240"></center>';
echo '<h1>Whoa, too many requests at once!</h1>';
echo '<p>Mallard needs a moment to catch up. Please wait a few seconds and try again.</p>';
echo page_foot();
