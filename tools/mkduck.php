<?php
// Generate the yellow rubber-duck logo (duck.gif) + favicon (favicon.gif) for
// DuckFind, with a TRANSPARENT background so they sit cleanly on light OR dark
// themes. Pass an output directory as argv[1] (defaults to this dir).
$W = 120; $H = 100;
$out = $argv[1] ?? __DIR__;

$im = imagecreatetruecolor($W, $H);
$white   = imagecolorallocate($im, 255, 255, 255);   // background -> made transparent below
imagefilledrectangle($im, 0, 0, $W, $H, $white);

$yellow   = imagecolorallocate($im, 255, 209,  0);
$yellowD  = imagecolorallocate($im, 225, 165,  0);   // shading
$orange   = imagecolorallocate($im, 255, 140,  0);
$orangeD  = imagecolorallocate($im, 205, 105,  0);
$black    = imagecolorallocate($im,  25,  25,  25);
$eyewhite = imagecolorallocate($im, 248, 248, 248);  // near-white so it isn't made transparent

// body
imagefilledellipse($im, 68, 70, 92, 52, $yellow);
imagefilledpolygon($im, [108, 62, 120, 50, 106, 74], $yellow);   // tail flip
// head
imagefilledellipse($im, 44, 38, 50, 48, $yellow);
// beak (facing left, blunt rubber-duck bill)
imagefilledpolygon($im, [26, 33, 3, 37, 3, 47, 26, 51], $orange);
imagefilledellipse($im, 5, 42, 8, 10, $orange);
imagefilledpolygon($im, [26, 44, 4, 47, 26, 51], $orangeD);
// wing + head/body seam
imagesetthickness($im, 3);
imagearc($im, 76, 72, 48, 30, 195, 345, $yellowD);
imagearc($im, 50, 54, 44, 22, 20, 160, $yellowD);
// eye
imagefilledellipse($im, 40, 32, 11, 11, $black);
imagefilledellipse($im, 38, 30,  4,  4, $eyewhite);

// favicon: nearest-neighbour scale keeps colours pure (no white fringe to leak transparency)
$fav = imagescale($im, 32, 32, IMG_NEAREST_NEIGHBOUR);

save_transparent($im,  $out . '/duck.gif');
save_transparent($fav, $out . '/favicon.gif');
imagedestroy($im);
imagedestroy($fav);
echo "wrote duck.gif + favicon.gif (transparent) to $out\n";

// Convert truecolor -> palette GIF with pure white as the transparent colour.
function save_transparent($img, string $path): void {
    imagetruecolortopalette($img, false, 255);
    $wi = imagecolorexact($img, 255, 255, 255);
    if ($wi < 0) $wi = imagecolorclosest($img, 255, 255, 255);
    imagecolortransparent($img, $wi);
    imagegif($img, $path);
}
