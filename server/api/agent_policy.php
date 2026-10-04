<?php
// api/agent_policy.php
// Agent goi API nay (dinh ky, hoac khi heartbeat bao co thay doi) de lay toan bo policy ap dung cho may nay.

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/helpers.php';

header('Content-Type: application/json; charset=utf-8');

// ---- 1. Xac thuc bang Bearer token (api_token cua device) ----
$headers = getallheaders();
$authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? '';

if (!preg_match('/Bearer\s+(.+)/', $authHeader, $m)) {
    http_response_code(401);
    echo json_encode(['error' => 'Thieu hoac sai dinh dang Authorization header. Can: Bearer <api_token>']);
    exit;
}
$apiToken = trim($m[1]);

$stmt = $pdo->prepare("SELECT * FROM devices WHERE api_token = ?");
$stmt->execute([$apiToken]);
$device = $stmt->fetch();

if (!$device) {
    http_response_code(401);
    echo json_encode(['error' => 'api_token khong hop le. Device chua duoc dang ky hoac token sai.']);
    exit;
}

// ---- 2. Device chua duoc gan Group -> chua co policy nao ca ----
if ($device['group_id'] === null) {
    echo json_encode([
        'hostname'            => $device['hostname'],
        'is_assigned'         => false,
        'applicable_policies' => [],
        'usb_whitelist'       => [],
        'network_blacklist'   => [],
        'note'                => 'Device chua duoc admin gan vao Group nao. Chua co policy ap dung.',
    ]);
    exit;
}

// ---- 3. Lay danh sach policy ap dung: theo Group HOAC theo Device cu the ----
$sql = "
    SELECT DISTINCT p.*
    FROM dlp_policies p
    LEFT JOIN dlp_policy_devices pd ON pd.policy_id = p.id
    WHERE p.is_active = 1
      AND (
            (p.target_type = 'GROUP'  AND p.target_group_id = ?)
         OR (p.target_type = 'DEVICE' AND pd.device_id = ?)
      )
";
$stmt = $pdo->prepare($sql);
$stmt->execute([$device['group_id'], $device['id']]);
$policies = $stmt->fetchAll();

$applicablePolicies = [];

foreach ($policies as $policy) {
    // Exit points
    $stmt = $pdo->prepare("SELECT exit_point_type FROM dlp_policy_exit_points WHERE policy_id = ?");
    $stmt->execute([$policy['id']]);
    $exitPoints = array_column($stmt->fetchAll(), 'exit_point_type');

    // File types
    $stmt = $pdo->prepare("
        SELECT ft.id, ft.extension, ft.category, ft.always_block_regardless_content
        FROM dlp_policy_file_types pft
        JOIN dlp_file_types ft ON ft.id = pft.file_type_id
        WHERE pft.policy_id = ?
    ");
    $stmt->execute([$policy['id']]);
    $fileTypes = array_map(function ($ft) {
        $ft['always_block_regardless_content'] = (bool)$ft['always_block_regardless_content'];
        return $ft;
    }, $stmt->fetchAll());

    // Content rules
    $stmt = $pdo->prepare("
        SELECT cr.id, cr.rule_name, cr.rule_type, cr.pattern, cr.category, cr.severity
        FROM dlp_policy_content_rules pcr
        JOIN content_rules cr ON cr.id = pcr.content_rule_id
        WHERE pcr.policy_id = ? AND cr.is_active = 1
    ");
    $stmt->execute([$policy['id']]);
    $contentRules = $stmt->fetchAll();

    // Exceptions (allowed locations / allowed files)
    $stmt = $pdo->prepare("SELECT exception_type, value FROM dlp_policy_exceptions WHERE policy_id = ?");
    $stmt->execute([$policy['id']]);
    $allowedLocations = [];
    $allowedFiles = [];
    foreach ($stmt->fetchAll() as $ex) {
        if ($ex['exception_type'] === 'ALLOWED_LOCATION') {
            $allowedLocations[] = $ex['value'];
        } else {
            $allowedFiles[] = $ex['value'];
        }
    }

    $applicablePolicies[] = [
        'policy_id'         => (int)$policy['id'],
        'name'              => $policy['name'],
        'action'            => $policy['action'], // BLOCK | REPORT_ONLY
        'exit_points'       => $exitPoints,
        'file_types'        => $fileTypes,
        'content_rules'     => $contentRules,
        'allowed_locations' => $allowedLocations,
        'allowed_files'     => $allowedFiles,
    ];
}

// ---- 4. USB whitelist (ap dung chung theo group cua device, hoac global neu group_id NULL) ----
$stmt = $pdo->prepare("
    SELECT serial_number, description
    FROM usb_whitelist
    WHERE group_id = ? OR group_id IS NULL
");
$stmt->execute([$device['group_id']]);
$usbWhitelist = $stmt->fetchAll();

// ---- 5. Network blacklist (global, dang active) ----
$stmt = $pdo->query("
    SELECT target_type, value, description
    FROM network_blacklist
    WHERE is_active = 1
");
$networkBlacklist = $stmt->fetchAll();

// ---- 6. Tra ket qua ----
echo json_encode([
    'hostname'            => $device['hostname'],
    'is_assigned'         => true,
    'group_id'            => (int)$device['group_id'],
    'applicable_policies' => $applicablePolicies,
    'usb_whitelist'       => $usbWhitelist,
    'network_blacklist'   => $networkBlacklist,
], JSON_UNESCAPED_UNICODE);