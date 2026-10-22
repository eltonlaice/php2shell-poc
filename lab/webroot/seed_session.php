<?php
// LAB ONLY. Creates a large, valid session file so that chain E can be
// exercised without first inflating a session through upload filenames.
// This is not an attack primitive; it exists so the stale-state verifier is
// reproducible. It only responds when the container is started with P2S_LAB=1
// (the bundled compose file sets it).
if (getenv('P2S_LAB') !== '1') {
    http_response_code(404);
    echo "not found\n";
    exit;
}

$sid = $_GET['sid'] ?? '';
$size = (int)($_GET['size'] ?? (24 * 1024 * 1024));

if (!preg_match('/^[A-Za-z0-9]{8,64}$/', $sid)) {
    http_response_code(400);
    echo "bad sid\n";
    exit;
}
if ($size < 1 || $size > 64 * 1024 * 1024) {
    http_response_code(400);
    echo "bad size\n";
    exit;
}

$path = rtrim(session_save_path(), '/') . '/sess_' . $sid;
$fh = fopen($path, 'wb');
if ($fh === false) {
    http_response_code(500);
    echo "cannot open session file\n";
    exit;
}
fwrite($fh, 'pad|s:' . $size . ':"');
$chunk = str_repeat('A', 1 << 20);
$left = $size;
while ($left > 0) {
    $n = min($left, 1 << 20);
    fwrite($fh, $n === 1 << 20 ? $chunk : substr($chunk, 0, $n));
    $left -= $n;
}
fwrite($fh, '";');
fclose($fh);

header('Content-Type: text/plain');
echo "seeded " . $size . " bytes at " . $path . "\n";
