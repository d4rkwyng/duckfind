<?php
require __DIR__ . '/lib.php';
http_response_code(503);
header('Content-Type: text/html; charset=iso-8859-1');
echo page_head(DUCKFIND_NAME . ' - too many ducks', true);
echo '<center><img src="/duck-maintenance.gif" alt="' . DUCKFIND_NAME . '" width="240" height="240"></center>';
echo '<h1>Whoa, too many ducks paddling at once!</h1>';
echo '<p>Even Mallard needs a breather sometimes. Try again in a few seconds.</p>';
echo page_foot();
