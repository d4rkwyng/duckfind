<?php
require __DIR__ . '/lib.php';
http_response_code(502);
header('Content-Type: text/html; charset=iso-8859-1');
echo page_head(DUCKFIND_NAME . ' - bad gateway', true);
echo '<center><img src="/duck-502.gif" alt="' . DUCKFIND_NAME . '" width="240" height="240"></center>';
echo '<h1>Mallard found the bridge out.</h1>';
echo '<p>A piece this page depends on did not answer. Try again in a moment.</p>';
echo page_foot();
