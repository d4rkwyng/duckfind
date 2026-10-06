<?php
require __DIR__ . '/lib.php';
http_response_code(403);
header('Content-Type: text/html; charset=iso-8859-1');
echo page_head(DUCKFIND_NAME . ' - not allowed', true);
echo '<center><img src="/duck-403.gif" alt="' . DUCKFIND_NAME . '" width="240" height="240"></center>';
echo '<h1>This duck is standing guard.</h1>';
echo '<p>You are not allowed to see that. If this seems wrong, let us know.</p>';
echo page_foot();
