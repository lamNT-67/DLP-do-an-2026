<?php
declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/api_common.php';
api_method('POST');
$token = api_token();
$data = api_json();
$hostname = api_string($data, 'hostname', 100, true);
$version = api_string($data, 'agent_version', 20);
$ip = api_string($data, 'ip_address', 45) ?? ($_SERVER['REMOTE_ADDR'] ?? null);
if ($ip !== null && filter_var($ip, FILTER_VALIDATE_IP) === false) api_error(400, 'Invalid IP address');
try {
    $device = api_device($pdo, $token, $hostname);
    $stmt = $pdo->prepare("UPDATE devices SET last_seen = NOW(), status = 'ONLINE', agent_version = COALESCE(?, agent_version), ip_address = COALESCE(?, ip_address) WHERE id = ?");
    $stmt->execute([$version, $ip, $device['id']]);
    echo json_encode(['status' => 'ok']);
} catch (PDOException $e) { api_db_error($e); }
