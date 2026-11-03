<?php
declare(strict_types=1);
// Run from Windows Task Scheduler using php.exe, not through an HTTP endpoint.
if (PHP_SAPI !== 'cli') { http_response_code(403); exit; }
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/wazuh_forwarder.php';
try {
    $stats = wazuh_flush($pdo, 25);
    echo gmdate('c') . ' Wazuh outbox ' . json_encode($stats) . PHP_EOL;
} catch (Throwable $ex) {
    error_log('[DLP Wazuh] worker failed: ' . $ex->getMessage());
    fwrite(STDERR, 'Wazuh flush failed' . PHP_EOL);
    exit(1);
}
