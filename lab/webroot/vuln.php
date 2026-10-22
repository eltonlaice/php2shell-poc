<?php
// Lab endpoint: deliberately vulnerable LFI sink for chain A.
$page = $_GET['page'] ?? '';
if ($page === '') {
    http_response_code(400);
    echo "missing page\n";
    exit;
}
include $page;
