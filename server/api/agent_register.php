<?php
/**
 * POST /api/agent_register.php
 * Body (JSON): { "hostname", "enrollment_key", "ip_address", "os_info", "username", "agent_version" }
 *
 * Agent goi endpoint nay CHI 1 LAN DUY NHAT khi cai dat lan dau (khong can Admin tao tay).
 * Server kiem tra enrollment_key hop le -> tu tao dong moi trong `devices`
 * voi group_id = NULL (hien thi la "Unassigned" trong Admin UI) -> sinh api_token rieng tra ve.
 *
 * Neu hostname da ton tai roi -> tra ve loi 409, huong dan dung lai token cu.
 */
header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/helpers.php';

function fail(int $code, string $message) {
    http_response_code($code);
    die(json_encode(['error' => $message]));
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    fail(405, 'Method not allowed, use POST');
}

$input = json_decode(file_get_contents('php://input'), true);
if (json_last_error() !== JSON_ERROR_NONE || !$input) {
    fail(400, 'Invalid JSON body');
}

$hostname = trim($input['hostname'] ?? '');
$enrollmentKey = trim($input['enrollment_key'] ?? '');

if ($hostname === '' || $enrollmentKey === '') {
    fail(400, 'Missing required field: hostname or enrollment_key');
}

$stmt = $pdo->prepare("SELECT id FROM enrollment_keys WHERE enrollment_key = ? AND is_active = 1");
$stmt->execute([$enrollmentKey]);
$key = $stmt->fetch();

if (!$key) {
    fail(403, 'Invalid or inactive enrollment key');
}

$stmt = $pdo->prepare("SELECT id, api_token FROM devices WHERE hostname = ?");
$stmt->execute([$hostname]);
$existing = $stmt->fetch();

if ($existing) {
    fail(409, 'Hostname already registered. Reuse the previously issued api_token instead of re-registering.');
}

$ipAddress = $input['ip_address'] ?? $_SERVER['REMOTE_ADDR'] ?? null;
$apiToken = generate_token();

$stmt = $pdo->prepare("
    INSERT INTO devices
    (hostname, ip_address, os_info, username, group_id, api_token, agent_version,
     status, enrolled_via_key_id, first_seen, last_seen)
    VALUES (?, ?, ?, ?, NULL, ?, ?, 'ONLINE', ?, NOW(), NOW())
");

try {
    $stmt->execute([
        $hostname,
        $ipAddress,
        $input['os_info'] ?? null,
        $input['username'] ?? null,
        $apiToken,
        $input['agent_version'] ?? null,
        $key['id'],
    ]);
} catch (PDOException $e) {
    fail(500, 'Failed to register device: ' . $e->getMessage());
}

echo json_encode([
    'status'     => 'registered',
    'device_id'  => (int)$pdo->lastInsertId(),
    'api_token'  => $apiToken,
    'note'       => 'Device is registered as Unassigned. An admin must assign it to a Group before policies apply.',
]);