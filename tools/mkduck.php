<?php
// Generate a yellow rubber-duck GIF logo for DuckFind.
$W = 120; $H = 100;
$im = imagecreatetruecolor($W, $H);

$white   = imagecolorallocate($im, 255, 255, 255);
$yellow  = imagecolorallocate($im, 255, 209,  0);
$yellowD = imagecolorallocate($im, 225, 165,  0);   // shading
$orange  = imagecolorallocate($im, 255, 140,  0);
$orangeD = imagecolorallocate($im, 205, 105,  0);
$black   = imagecolorallocate($im,  25,  25,  25);
$eyewhite= imagecolorallocate($im, 255, 255, 255);

imagefilledrectangle($im, 0, 0, $W, $H, $white);

// --- body (big rounded blob, lower-right) ---
imagefilledellipse($im, 68, 70, 92, 52, $yellow);
// tail flip (little triangle at right)
imagefilledpolygon($im, [108, 62, 120, 50, 106, 74], $yellow);

// --- head (upper-left) ---
imagefilledellipse($im, 44, 38, 50, 48, $yellow);

// --- beak (facing left, blunt rubber-duck bill) ---
imagefilledpolygon($im, [26, 33, 3, 37, 3, 47, 26, 51], $orange);
imagefilledellipse($im, 5, 42, 8, 10, $orange);               // rounded front of bill
imagefilledpolygon($im, [26, 44, 4, 47, 26, 51], $orangeD);   // lower-bill shade

// --- wing (arc on the body) ---
imagesetthickness($im, 3);
imagearc($im, 76, 72, 48, 30, 195, 345, $yellowD);
// seam where head meets body
imagearc($im, 50, 54, 44, 22, 20, 160, $yellowD);

// --- eye ---
imagefilledellipse($im, 40, 32, 11, 11, $black);
imagefilledellipse($im, 38, 30,  4,  4, $eyewhite);

imagegif($im, __DIR__ . '/duck.gif');
imagedestroy($im);
echo "wrote duck.gif\n";
