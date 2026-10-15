<?php
declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/api_common.php';
api_method('POST');
$data = api_json();
$hostname = api_string($data, 'hostname', 100, true);
$keyValue = api_string($data, 'enrollment_key', 64, true);
if (!preg_match('/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/', $hostname)) api_error(400, 'Invalid hostname');
$ip = api_string($data, 'ip_address', 45) ?? ($_SERVER['REMOTE_ADDR'] ?? null);
if ($ip !== null && filter_var($ip, FILTER_VALIDATE_IP) === false) api_error(400, 'Invalid IP address');
$os = api_string($data, 'os_info', 150);
$username = api_string($data, 'username', 100);
$version = api_string($data, 'agent_version', 20);
try {
    $stmt = $pdo->prepare('SELECT id FROM enrollment_keys WHERE enrollment_key = ? AND is_active = 1');
    $stmt->execute([$keyValue]);
    $key = $stmt->fetch();
    if (!$key) api_error(403, 'Invalid or inactive enrollment key');
    $stmt = $pdo->prepare('SELECT id FROM devices WHERE hostname = ?');
    $stmt->execute([$hostname]);
    if ($stmt->fetch()) api_error(409, 'Hostname already registered; reuse existing token or contact admin');
    $token = generate_token();
    $stmt = $pdo->prepare("INSERT INTO devices (hostname, ip_address, os_info, username, group_id, api_token, agent_version, status, enrolled_via_key_id, first_seen, last_seen) VALUES (?, ?, ?, ?, NULL, ?, ?, 'ONLINE', ?, NOW(), NOW())");
    $stmt->execute([$hostname, $ip, $os, $username, $token, $version, $key['id']]);
    http_response_code(201);
    echo json_encode(['status' => 'registered', 'device_id' => (int)$pdo->lastInsertId(), 'api_token' => $token, 'note' => 'Unassigned until an admin assigns a group or device policy']);
} catch (PDOException $e) {
    if ($e->getCode() === '23000') api_error(409, 'Device already registered');
    api_db_error($e);
}
