<?php
// Lab endpoint: starts a session so upload_progress has a target.
session_start();
header('Content-Type: application/json');
echo json_encode([
    'php' => PHP_VERSION,
    'sapi' => php_sapi_name(),
    'upload_progress' => ini_get('session.upload_progress.enabled'),
    'serialize_handler' => ini_get('session.serialize_handler'),
    'session_id' => session_id(),
]), "\n";
