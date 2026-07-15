<?php
// DuckFind PDF viewer — read a PDF on a vintage browser. PDFs are opaque to
// old machines; DuckFind renders them server-side with poppler (pdftotext /
// pdftoppm) and hands back either extracted text as plain HTML (default: light,
// fast, reflows to a narrow screen) or each page rasterised through the same
// GIF pipeline as the image proxy (grayscale / 1-bit modes included) when
// layout and figures matter. read.php routes application/pdf here automatically.
//
// This needs the poppler-utils binaries on the host; without them the page just
// offers a download link, so the "just PHP extensions" install still works —
// PDF support is an optional extra, like AI answers.
require __DIR__ . '/lib.php';
// Own rate bucket: rendering a PDF spawns a poppler process (heaviest request
// on the box), so it gets a tighter limit than the generous 'read' bucket.
if (!df_rate('pdf')) df_rate_block();

define('PDF_MAX_BYTES', 25000000);   // 25 MB source cap
define('PDF_TEXT_PAGES', 30);        // text mode extracts the first N pages
define('PDF_TIMEOUT', 25);           // seconds per poppler invocation
define('PDF_IMG_W', 600);            // rasterised page width (matches the page column)

$url  = df_input('url');
if ($url !== '' && !preg_match('#^[a-z]+://#i', $url)) $url = 'https://' . $url;
$year = preg_replace('/\D/', '', (string)($_GET['year'] ?? ''));
$mode = (($_GET['m'] ?? '') === 'img') ? 'img' : 'text';
$im   = strtolower($_GET['im'] ?? ($_COOKIE['df_mode'] ?? 'color'));
if (!in_array($im, ['color', 'gray', 'bw'], true)) $im = 'color';
$page = max(1, (int)($_GET['pg'] ?? 1));
$yp   = $year !== '' ? '&amp;year=' . $year : '';

// ---- rasterised-page GIF sub-request (the <img> src for image mode) ----------
if (isset($_GET['gif'])) {
    if (!preg_match('#^https?://#i', $url)) { pdf_blank(); }
    $ckey = "pdfpg:$im:$page:$year:$url";
    if (($hit = df_cache_get($ckey, 604800)) !== null) { pdf_emit_gif($hit); }
    $tmp = pdf_tmp($url, $year);
    if ($tmp === null || pdf_bin('pdftoppm') === '') { pdf_blank(); }
    $prefix = $tmp . '-p';
    pdf_run([pdf_bin('pdftoppm'), '-png', '-scale-to-x', (string)PDF_IMG_W, '-scale-to-y', '-1',
             '-f', (string)$page, '-l', (string)$page, '-singlefile', $tmp, $prefix]);
    @unlink($tmp);
    $png = @file_get_contents($prefix . '.png');
    @unlink($prefix . '.png');
    if ($png === false) { pdf_blank(); }
    $gif = pdf_png_to_gif($png, $im);
    if ($gif === null) { pdf_blank(); }
    df_cache_put($ckey, $gif);
    pdf_emit_gif($gif);
}

header('Content-Type: text/html; charset=iso-8859-1');

// ---- landing / no URL --------------------------------------------------------
if (!preg_match('#^https?://#i', $url)) {
    echo page_head(DUCKFIND_NAME . ' - PDF viewer');
    echo pdf_header_form('');
    echo '<p>Paste a link to a PDF and read it as plain HTML (or page images) on any '
       . 'old machine. Most PDF links in search results open here automatically.</p>';
    echo page_foot(); exit;
}

$havText = pdf_bin('pdftotext') !== '';
$havImg  = pdf_bin('pdftoppm') !== '';
$dl = '<p>[<a href="' . e($url) . '">download the original PDF</a>]</p>';

if (!$havText && !$havImg) {
    echo page_head(DUCKFIND_NAME . ' - PDF', true) . pdf_header_form($url)
       . '<p><b>This DuckFind can\'t render PDFs</b> (poppler-utils is not installed on '
       . 'the server).</p>' . $dl . page_foot();
    exit;
}

// ---- fetch + basic metadata --------------------------------------------------
$tmp = pdf_tmp($url, $year);
if ($tmp === null) {
    echo page_head(DUCKFIND_NAME . ' - PDF', true) . pdf_header_form($url)
       . '<p><b>Could not load that PDF.</b> It may be too large (max '
       . (int)(PDF_MAX_BYTES / 1000000) . ' MB), missing, or not a PDF.</p>' . $dl . page_foot();
    exit;
}
$pages = 1; $title = '';
if (pdf_bin('pdfinfo') !== '') {
    $info = (string)pdf_run([pdf_bin('pdfinfo'), $tmp]);
    if (preg_match('/^Pages:\s+(\d+)/m', $info, $m)) $pages = max(1, (int)$m[1]);
    // [^\S\n]+ (spaces/tabs, not newlines) so an empty "Title:" line doesn't let
    // \s+ span the newline and capture the next pdfinfo field (e.g. "Subject:")
    if (preg_match('/^Title:[^\S\n]+(.+)$/m', $info, $m)) $title = trim($m[1]);
}
if ($mode === 'img' && !$havImg) $mode = 'text';
if ($mode === 'text' && !$havText) $mode = 'img';

echo page_head(DUCKFIND_NAME . ' - PDF' . ($title !== '' ? ': ' . $title : ''), true);
echo pdf_header_form($url);

// mode + source toolbar
$base = '/pdf.php?url=' . htmlspecialchars(urlencode($url), ENT_QUOTES) . $yp;
$tog  = 'view: '
      . ($mode === 'text' ? '<b>text</b>' : '<a href="' . $base . '&amp;m=text">text</a>') . ' '
      . ($mode === 'img'  ? '<b>page images</b>' : '<a href="' . $base . '&amp;m=img">page images</a>');
echo '<font size="1">Reading PDF: <a href="' . e($url) . '">' . e($url) . '</a>'
   . ' &middot; ' . $tog . ' &middot; [<a href="' . e($url) . '">download</a>]</font><hr>';
if ($title !== '') echo '<h1>' . e($title) . '</h1>';

if ($mode === 'text') {
    $ckey = "pdftxt:$year:$url";
    $txt = df_cache_get($ckey, 604800);
    if ($txt === null) {
        $txt = (string)pdf_run([pdf_bin('pdftotext'), '-nopgbrk', '-f', '1',
                                '-l', (string)PDF_TEXT_PAGES, $tmp, '-']);
        df_cache_put($ckey, $txt);
    }
    @unlink($tmp);
    $txt = df_to_utf8($txt, 'text/plain; charset=utf-8');
    $paras = preg_split('/\n\s*\n/', trim($txt));
    if (!$paras || (count($paras) === 1 && $paras[0] === '')) {
        echo '<p><b>No selectable text in this PDF</b> (it may be scanned images). '
           . 'Try <a href="' . $base . '&amp;m=img">page images</a>.</p>';
    } else {
        foreach ($paras as $p) {
            $p = trim($p);
            if ($p !== '') echo '<p>' . nl2br(e($p), false) . '</p>';
        }
    }
    if ($pages > PDF_TEXT_PAGES) {
        echo '<hr><p><font size="1">(showing the first ' . PDF_TEXT_PAGES . ' of ' . $pages
           . ' pages)</font></p>';
    }
} else {
    @unlink($tmp);
    $page = min($page, $pages);
    $showImg = (($_COOKIE['df_img'] ?? '1') !== '0');
    if (!$showImg) {
        echo '<p>Page images are off in your <a href="/settings.php">settings</a>. '
           . '<a href="' . $base . '&amp;m=text">Read as text instead.</a></p>';
    } else {
        echo pdf_page_nav($base, $page, $pages, $im);
        echo '<img src="' . $base . '&amp;m=img&amp;pg=' . $page . '&amp;im=' . $im
           . '&amp;gif=1" width="' . PDF_IMG_W . '" border="1" vspace="4" alt="Page ' . $page . '">';
        echo '<br>' . pdf_page_nav($base, $page, $pages, $im);
    }
}
echo page_foot();

// ============================================================================
// helpers
// ============================================================================
function pdf_header_form(string $url): string {
    return '<form action="/pdf.php" method="get"><a href="/"><b>' . DUCKFIND_NAME . '</b></a>&nbsp;&nbsp;'
         . 'PDF: <input type="text" name="url" size="30" value="' . e($url) . '">&nbsp;'
         . '<input type="submit" value="Read"></form>';
}

function pdf_page_nav(string $base, int $page, int $pages, string $im): string {
    $link = fn($p, $label) => '<a href="' . $base . '&amp;m=img&amp;im=' . $im . '&amp;pg=' . $p
                            . '">' . $label . '</a>';
    $prev = $page > 1     ? $link($page - 1, '&lt; prev') : 'prev';
    $next = $page < $pages ? $link($page + 1, 'next &gt;') : 'next';
    return '<font size="1">' . $prev . ' &nbsp; page ' . $page . ' of ' . $pages
         . ' &nbsp; ' . $next . '</font>';
}

// Path to a poppler binary, or '' if absent (no shell needed).
function pdf_bin(string $name): string {
    static $cache = [];
    if (isset($cache[$name])) return $cache[$name];
    foreach (['/usr/bin/', '/usr/local/bin/', '/bin/'] as $d) {
        if (is_executable($d . $name)) return $cache[$name] = $d . $name;
    }
    return $cache[$name] = '';
}

// Run a command as an argv array (no shell = no injection), wrapped in the
// `timeout` binary when available so a malicious PDF can't hang a worker.
// Returns stdout, or null on failure.
function pdf_run(array $cmd): ?string {
    $to = pdf_bin('timeout');
    if ($to !== '') array_unshift($cmd, $to, (string)PDF_TIMEOUT);
    $p = @proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    if (!is_resource($p)) return null;
    $out = stream_get_contents($pipes[1]);
    fclose($pipes[1]); fclose($pipes[2]);
    proc_close($p);
    return $out === false ? null : $out;
}

// Fetch the PDF (cached, SSRF-safe, size-capped) and write it to a temp file for
// poppler; returns the path (caller unlinks) or null. Verifies the %PDF header.
function pdf_tmp(string $url, string $year): ?string {
    if ($year !== '') {
        $ts = strlen($year) === 4 ? $year . '0601' : $year;
        $ts = substr(str_pad($ts, 14, '0'), 0, 14);
        $res = df_wayback_get($ts, $url, 604800, PDF_MAX_BYTES);
    } else {
        $res = http_get_cached($url, 604800, PDF_MAX_BYTES);
    }
    // The byte cap aborts the transfer mid-stream, leaving a truncated file that
    // still starts with %PDF; poppler would then render it partial/garbled.
    // Treat a body at (or over) the cap as "too large" and refuse.
    if ($res === null || strncmp((string)$res['body'], '%PDF', 4) !== 0
        || strlen((string)$res['body']) >= PDF_MAX_BYTES) return null;
    $dir = (string)df_cfg('cache_dir', sys_get_temp_dir() . '/duckfind-cache') . '/pdftmp';
    if (!is_dir($dir)) @mkdir($dir, 0700, true);
    // every request unlinks its own temp file; this only mops up a temp left by
    // a render that was killed mid-flight (rare). ~2% of calls, files > 1h old.
    if (mt_rand(1, 50) === 1) {
        foreach (glob($dir . '/*.pdf') ?: [] as $old) {
            if (@filemtime($old) < time() - 3600) @unlink($old);
        }
    }
    try { $name = bin2hex(random_bytes(8)); }
    catch (\Throwable $e) { $name = md5($url . mt_rand()); }
    $path = $dir . '/' . $name . '.pdf';
    if (@file_put_contents($path, $res['body']) === false) return null;
    return $path;
}

// Rasterised PNG page -> GIF in the requested colour mode (same palette rules as
// the image proxy: 64-gray, dithered 1-bit, or a plain palette).
function pdf_png_to_gif(string $png, string $im): ?string {
    $img = @imagecreatefromstring($png);
    if ($img === false) return null;
    if ($im === 'gray') {
        imagefilter($img, IMG_FILTER_GRAYSCALE);
        imagetruecolortopalette($img, false, 64);
    } elseif ($im === 'bw') {
        imagefilter($img, IMG_FILTER_GRAYSCALE);
        imagefilter($img, IMG_FILTER_CONTRAST, -20);
        imagetruecolortopalette($img, true, 2);
    } else {
        imagetruecolortopalette($img, false, 255);
    }
    ob_start();
    imagegif($img);
    $gif = ob_get_clean();
    imagedestroy($img);
    return $gif;
}

function pdf_emit_gif(string $gif): void {
    header('Content-Type: image/gif');
    header('Expires: ' . gmdate('D, d M Y H:i:s', time() + 86400) . ' GMT');
    header('Cache-Control: public, max-age=86400');
    echo $gif; exit;
}

function pdf_blank(): void {
    header('Content-Type: image/gif');
    header('Cache-Control: public, max-age=3600');
    $im = imagecreate(1, 1);
    imagecolortransparent($im, imagecolorallocate($im, 255, 255, 255));
    imagegif($im);
    imagedestroy($im);
    exit;
}
