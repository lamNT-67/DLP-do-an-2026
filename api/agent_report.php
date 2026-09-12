<?php
/**
 * POST /api/agent_report.php
 * Header: Authorization: Bearer {token}
 * Body (JSON): xem docs/API_CONTRACT.md
 *
 * Agent goi endpoint nay moi khi co su kien tai exit point can ghi nhan
 * (cho phep / canh bao / chan).
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

if (empty($token)) {
    fail(401, 'Missing API token');
}

$raw = file_get_contents('php://input');
$input = json_decode($raw, true);

if (json_last_error() !== JSON_ERROR_NONE || !$input) {
    fail(400, 'Invalid JSON body');
}

$required = ['hostname', 'exit_point_type', 'policy_state', 'action_taken', 'occurred_at'];
foreach ($required as $field) {
    if (empty($input[$field])) {
        fail(400, "Missing required field: $field");
    }
}

$hostname = $input['hostname'];

$stmt = $pdo->prepare("SELECT id FROM endpoints WHERE hostname = ? AND api_token = ?");
$stmt->execute([$hostname, $token]);
$endpoint = $stmt->fetch();

if (!$endpoint) {
    fail(403, 'Invalid hostname or token');
}

// matched_rule_ids co the gui len dang mang JSON [1,3,5] hoac chuoi "1,3,5" - chuan hoa ve chuoi
$matchedRuleIds = $input['matched_rule_ids'] ?? null;
if (is_array($matchedRuleIds)) {
    $matchedRuleIds = implode(',', $matchedRuleIds);
}

$stmt = $pdo->prepare("
    INSERT INTO violation_summary
    (endpoint_id, exit_point_type, policy_state, action_taken, file_path,
     file_hash_sha256, matched_rule_ids, confidence_score, destination_value,
     process_name, occurred_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
");

try {
    $stmt->execute([
        $endpoint['id'],
        $input['exit_point_type'],
        $input['policy_state'],
        $input['action_taken'],
        $input['file_path'] ?? null,
        $input['file_hash_sha256'] ?? null,
        $matchedRuleIds,
        $input['confidence_score'] ?? null,
        $input['destination_value'] ?? null,
        $input['process_name'] ?? null,
        // Chap nhan ca ISO8601 (2026-08-28T10:15:32Z) lan "Y-m-d H:i:s"
        date('Y-m-d H:i:s', strtotime($input['occurred_at'])),
    ]);
} catch (PDOException $e) {
    fail(400, 'Invalid data: ' . $e->getMessage());
}

echo json_encode(['status' => 'ok', 'id' => $pdo->lastInsertId()]);
