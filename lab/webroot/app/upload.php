<?php
// Lab endpoint: uses the php_serialize session handler.
ini_set('session.serialize_handler', 'php_serialize');
session_start();
header('Content-Type: text/plain');
echo "app upload endpoint, handler=" . ini_get('session.serialize_handler') . "\n";
