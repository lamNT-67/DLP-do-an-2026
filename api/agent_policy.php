<?php
/**
 * GET /api/agent_policy.php?hostname={hostname}
 * Header: Authorization: Bearer {token}
 */
header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/../config/database.php';

function fail(int $code, string $message) {
    http_response_code($code);
    die(json_encode(['error' => $message]));
}

$headers = getallheaders();
$authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? '';
$token = trim(str_replace('Bearer', '', $authHeader));

if (empty($token)) {
    fail(401, 'Missing API token');
}

$hostname = $_GET['hostname'] ?? '';
if (empty($hostname)) {
    fail(400, 'Missing hostname parameter');
}

$stmt = $pdo->prepare("SELECT id, group_id FROM devices WHERE hostname = ? AND api_token = ?");
$stmt->execute([$hostname, $token]);
$device = $stmt->fetch();

if (!$device) {
    fail(403, 'Invalid hostname or token');
}

$deviceId = $device['id'];
$groupId = $device['group_id'];

$pdo->prepare("UPDATE devices SET last_seen = NOW(), status = 'ONLINE' WHERE id = ?")
    ->execute([$deviceId]);

$stmt = $pdo->prepare("
    SELECT DISTINCT p.*
    FROM dlp_policies p
    LEFT JOIN dlp_policy_devices pd ON pd.policy_id = p.id
    WHERE p.is_active = 1
      AND (
            (p.target_type = 'GROUP'  AND p.target_group_id = ?)
         OR (p.target_type = 'DEVICE' AND pd.device_id = ?)
      )
");
$stmt->execute([$groupId, $deviceId]);
$policyRows = $stmt->fetchAll();

$applicablePolicies = [];

foreach ($policyRows as $p) {
    $policyId = $p['id'];

    $stmt2 = $pdo->prepare("SELECT exit_point_type FROM dlp_policy_exit_points WHERE policy_id = ?");
    $stmt2->execute([$policyId]);
    $exitPoints = array_column($stmt2->fetchAll(), 'exit_point_type');

    $stmt2 = $pdo->prepare("
        SELECT ft.extension, ft.category, ft.always_block_regardless_content
        FROM dlp_policy_file_types pft
        JOIN dlp_file_types ft ON pft.file_type_id = ft.id
        WHERE pft.policy_id = ?
    ");
    $stmt2->execute([$policyId]);
    $fileTypes = $stmt2->fetchAll();
    foreach ($fileTypes as &$ft) {
        $ft['always_block_regardless_content'] = (bool)$ft['always_block_regardless_content'];
    }
    unset($ft);

    $stmt2 = $pdo->prepare("
        SELECT cr.id, cr.rule_name, cr.rule_type, cr.pattern, cr.category, cr.severity
        FROM dlp_policy_content_rules pcr
        JOIN content_rules cr ON pcr.content_rule_id = cr.id
        WHERE pcr.policy_id = ? AND cr.is_active = 1
    ");
    $stmt2->execute([$policyId]);
    $rules = $stmt2->fetchAll();

    $applicablePolicies[] = [
        'policy_id'      => (int)$policyId,
        'policy_name'    => $p['name'],
        'action'         => $p['action'],
        'exit_points'    => $exitPoints,
        'file_types'     => $fileTypes,
        'content_rules'  => $rules,
    ];
}

$stmt = $pdo->prepare("SELECT serial_number FROM usb_whitelist WHERE group_id = ? OR group_id IS NULL");
$stmt->execute([$groupId]);
$usbWhitelist = array_column($stmt->fetchAll(), 'serial_number');

$stmt = $pdo->query("SELECT target_type, value FROM network_blacklist WHERE is_active = 1");
$networkBlacklist = $stmt->fetchAll();

echo json_encode([
    'hostname'            => $hostname,
    'is_assigned'         => $groupId !== null,
    'applicable_policies' => $applicablePolicies,
    'usb_whitelist'       => $usbWhitelist,
    'network_blacklist'   => $networkBlacklist,
], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);