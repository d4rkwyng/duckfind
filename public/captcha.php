<?php
// Over-cap captcha (see df_captcha_block() in lib.php).
//   GET  ?c=<challenge>   the picture (no-store GIF)
//   POST c, a, r          check the answer; right: set the df_cap token and go
//                         back to r (a same-site path); wrong: a fresh captcha.
require __DIR__ . '/lib.php';
if (!df_rate('captcha')) df_rate_block();   // per-IP: bounds guessing

$c = df_str($_POST['c'] ?? ($_GET['c'] ?? ''));
if (strtoupper(df_str($_SERVER['REQUEST_METHOD'] ?? 'GET')) !== 'POST') {
    if (!df_captcha_challenge_ok($c)) { http_response_code(404); exit; }
    header('Content-Type: image/gif');
    header('Cache-Control: no-store');
    header('Expires: 0');                    // HTTP/1.0 browsers ignore Cache-Control
    echo df_captcha_gif($c);
    exit;
}

$r = df_captcha_return(df_str($_POST['r'] ?? '/'));
header('Content-Type: text/html; charset=iso-8859-1');
header('Cache-Control: no-store');
if (!df_captcha_check($c, df_str($_POST['a'] ?? ''))) {
    df_daily_inc('capfailed');
    http_response_code(403);
    echo df_captcha_form($r, df_captcha_challenge_ok($c)
        ? 'Those letters did not match. Please try this new picture.'
        : 'That picture had expired. Please try this new one.');
    exit;
}
df_daily_inc('capsolved');
setcookie('df_cap', df_captcha_token(), [
    'expires' => time() + DF_CAPTCHA_TOKEN_TTL, 'path' => '/', 'samesite' => 'Lax', 'httponly' => true,
]);
// 302 plus a body with a meta refresh and a plain link, for browsers that
// don't follow a redirect after a POST.
header('Location: ' . $r, true, 302);
echo page_head(DUCKFIND_NAME . ' - thanks', true, '', '<meta http-equiv="refresh" content="0; url=' . e($r) . '">')
   . '<p>Thanks. <a href="' . e($r) . '">Continue</a></p>' . page_foot();
