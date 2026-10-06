<?php
require __DIR__ . '/lib.php';
http_response_code(500);
header('Content-Type: text/html; charset=iso-8859-1');
echo page_head(DUCKFIND_NAME . ' - something broke', true);
echo '<center><img src="/duck-500.gif" alt="' . DUCKFIND_NAME . '" width="240" height="240"></center>';
echo '<h1>Mallard hit a snag.</h1>';
echo '<p>Something went wrong on our end. Try again in a moment -- if it keeps happening, let us know.</p>';
echo page_foot();
