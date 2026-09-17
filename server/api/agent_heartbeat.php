<?php
/**
 * POST /api/agent_heartbeat.php
 * Header: Authorization: Bearer {token}
 * Body (JSON): { "hostname": "...", "agent_version": "..." }
 *
 * Agent goi endpoint nay dinh ky (VD: moi 30-60s) de bao con hoat dong.
 * Neu server khong nhan duoc heartbeat qua lau, co the coi endpoint la OFFLINE
 * (xu ly bang 1 cron/job rieng, xem ghi chu trong dashboard.php).
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

$stmt = $pdo->prepare("
    UPDATE endpoints
    SET last_seen = NOW(), status = 'ONLINE', agent_version = ?
    WHERE hostname = ? AND api_token = ?
");
$stmt->execute([
    $input['agent_version'] ?? null,
    $hostname,
    $token,
]);

if ($stmt->rowCount() === 0) {
    fail(403, 'Invalid hostname or token');
}

echo json_encode(['status' => 'ok']);
