<?php
declare(strict_types=1);

/**
 * Server-side DLP -> Wazuh TCP syslog outbox.
 * No Agent-side SIEM connection; call enqueue after the DLP log row is stored.
 */
function wazuh_enqueue(PDO $pdo, int $logId): void {
    // No destination configured => DLP works normally, without accumulating a queue.
    $config = $pdo->query("SELECT siem_ip, siem_port FROM wazuh_settings WHERE id=1")->fetch(PDO::FETCH_ASSOC);
    if (!$config || filter_var($config['siem_ip'], FILTER_VALIDATE_IP) === false ||
        (int)$config['siem_port'] < 1 || (int)$config['siem_port'] > 65535) return;
    $stmt = $pdo->prepare('INSERT IGNORE INTO dlp_wazuh_outbox (log_id) VALUES (?)');
    $stmt->execute([$logId]);
}

/** Send one bounded batch. Designed for CLI cron or a short post-insert attempt. */
function wazuh_flush(PDO $pdo, int $limit = 10): array {
    $stats = ['sent' => 0, 'failed' => 0, 'skipped' => 0];
    $config = $pdo->query("SELECT siem_ip, siem_port FROM wazuh_settings WHERE id=1")->fetch(PDO::FETCH_ASSOC);
    if (!$config || filter_var($config['siem_ip'], FILTER_VALIDATE_IP) === false ||
        (int)$config['siem_port'] < 1 || (int)$config['siem_port'] > 65535) return $stats;
    $ip = (string)$config['siem_ip'];
    $port = (int)$config['siem_port'];

    $limit = max(1, min($limit, 50));
    $stmt = $pdo->query("SELECT q.log_id
        FROM dlp_wazuh_outbox q
        WHERE q.sent_at IS NULL AND q.next_attempt_at <= UTC_TIMESTAMP()
          AND (q.locked_until IS NULL OR q.locked_until < UTC_TIMESTAMP())
        ORDER BY q.log_id ASC LIMIT " . $limit);
    foreach ($stmt->fetchAll(PDO::FETCH_COLUMN) as $logId) {
        $logId = (int)$logId;
        // Atomic reservation: other PHP requests / scheduled workers skip this event.
        $claim = $pdo->prepare("UPDATE dlp_wazuh_outbox
            SET locked_until = DATE_ADD(UTC_TIMESTAMP(), INTERVAL 15 SECOND)
            WHERE log_id = ? AND sent_at IS NULL AND next_attempt_at <= UTC_TIMESTAMP()
              AND (locked_until IS NULL OR locked_until < UTC_TIMESTAMP())");
        $claim->execute([$logId]);
        if ($claim->rowCount() !== 1) { $stats['skipped']++; continue; }

        try {
            $read = $pdo->prepare("SELECT l.id, d.hostname, l.policy_id, l.exit_point_type,
                    l.action_taken, l.file_path, l.file_hash_sha256, l.matched_rule_ids,
                    l.confidence_score, l.destination_value, l.process_name, l.occurred_at
                FROM logs l JOIN devices d ON d.id=l.device_id WHERE l.id=?");
            $read->execute([$logId]);
            $event = $read->fetch(PDO::FETCH_ASSOC);
            if (!$event) throw new RuntimeException('Source DLP event not found');
            $json = json_encode([
                'integration' => 'DLPServer',
                'log_id' => (int)$event['id'],
                'hostname' => $event['hostname'],
                'policy_id' => $event['policy_id'] === null ? null : (int)$event['policy_id'],
                'exit_point_type' => $event['exit_point_type'],
                'action_taken' => $event['action_taken'],
                'file_path' => $event['file_path'],
                'file_hash_sha256' => $event['file_hash_sha256'],
                'matched_rule_ids' => $event['matched_rule_ids'] === null ? [] :
                    array_values(array_filter(array_map('intval', explode(',', $event['matched_rule_ids'])))),
                'confidence_score' => $event['confidence_score'],
                'destination_value' => $event['destination_value'],
                'process_name' => $event['process_name'],
                'occurred_at' => $event['occurred_at'] . 'Z',
            ], JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR);
            $host = preg_replace('/[^a-zA-Z0-9.\\-]/', '-', (string)$event['hostname']);
            $host = substr($host ?: 'dlp-server', 0, 80);
            // RFC3164-like header + newline-delimited JSON; no file bytes or auth tokens.
            $message = '<134>' . gmdate('M d H:i:s') . ' ' . $host . ' DLPServer: ' . $json . "\n";
            if (strlen($message) > 8192) throw new RuntimeException('Event too large for syslog');
            $address = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? "[$ip]" : $ip;
            $errno = 0; $errstr = '';
            $socket = @stream_socket_client('tcp://' . $address . ':' . $port,
                $errno, $errstr, 1.5, STREAM_CLIENT_CONNECT);
            if (!$socket) throw new RuntimeException('TCP connect failed: ' . $errstr);
            try {
                stream_set_timeout($socket, 2);
                $total = strlen($message); $offset = 0;
                while ($offset < $total) {
                    $n = @fwrite($socket, substr($message, $offset));
                    if ($n === false || $n === 0) throw new RuntimeException('TCP write failed');
                    $offset += $n;
                }
            } finally {
                fclose($socket);
            }
            $done = $pdo->prepare("UPDATE dlp_wazuh_outbox SET sent_at=UTC_TIMESTAMP(),
                locked_until=NULL, last_error=NULL WHERE log_id=?");
            $done->execute([$logId]);
            $stats['sent']++;
        } catch (Throwable $ex) {
            $retry = $pdo->prepare("UPDATE dlp_wazuh_outbox
                SET attempts=attempts+1, locked_until=NULL,
                    next_attempt_at=DATE_ADD(UTC_TIMESTAMP(), INTERVAL LEAST(300, POW(2, LEAST(attempts,8))) SECOND),
                    last_error=? WHERE log_id=?");
            $retry->execute([substr($ex->getMessage(), 0, 250), $logId]);
            error_log('[DLP Wazuh] log_id=' . $logId . ': ' . $ex->getMessage());
            $stats['failed']++;
        }
    }
    return $stats;
}
