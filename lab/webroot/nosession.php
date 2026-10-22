<?php
// Lab endpoint: no session_start(), used as the chain E consumer.
header('Content-Type: text/plain');
echo "php " . PHP_VERSION . " sapi " . php_sapi_name() . "\n";
echo "no session_start here\n";
