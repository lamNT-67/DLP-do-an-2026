<?php
/**
 * POST /api/agent_heartbeat.php
 * Header: Authorization: Bearer {token}
 * Body: { hostname, agent_version, ip_address? }
 */
header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/../config/database.php';

function fail(int $code, string $message) {
    http_response_code($code);
    die(json_encode(['error' => $message]));
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    fail(405, 'Method not allowed, use POST');
}

$headers = getallheaders();
$authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? '';
$token = trim(str_replace('Bearer', '', $authHeader));

$input = json_decode(file_get_contents('php://input'), true);
$hostname = $input['hostname'] ?? '';

if (empty($token) || empty($hostname)) {
    fail(400, 'Missing token or hostname');
}

$ipAddress = $input['ip_address'] ?? $_SERVER['REMOTE_ADDR'] ?? null;

$stmt = $pdo->prepare("
    UPDATE devices
    SET last_seen = NOW(), status = 'ONLINE', agent_version = ?, ip_address = COALESCE(?, ip_address)
    WHERE hostname = ? AND api_token = ?
");
$stmt->execute([
    $input['agent_version'] ?? null,
    $ipAddress,
    $hostname,
    $token,
]);

if ($stmt->rowCount() === 0) {
    fail(403, 'Invalid hostname or token');
}

echo json_encode(['status' => 'ok']);