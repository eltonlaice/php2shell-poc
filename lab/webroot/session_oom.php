<?php
// Lab endpoint: decoding a large session exhausts memory_limit.
session_start();
header('Content-Type: text/plain');
echo "decoded session with " . count($_SESSION) . " keys\n";
