<?php
/**
 * GET /api/agent_policy.php?hostname={hostname}
 * Header: Authorization: Bearer {token}
 *
 * Agent goi endpoint nay dinh ky (VD: moi 60s) de lay policy moi nhat.
 */
header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/../config/database.php';

function fail(int $code, string $message) {
    http_response_code($code);
    die(json_encode(['error' => $message]));
}

// --- Lay token tu header Authorization ---
$headers = getallheaders();
$authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? '';
$token = trim(str_replace('Bearer', '', $authHeader));

if (empty($token)) {
    fail(401, 'Missing API token');
}

// --- Lay hostname tu query string ---
$hostname = $_GET['hostname'] ?? '';
if (empty($hostname)) {
    fail(400, 'Missing hostname parameter');
}

// --- Kiem tra token khop voi endpoint ---
$stmt = $pdo->prepare("SELECT id, group_id FROM endpoints WHERE hostname = ? AND api_token = ?");
$stmt->execute([$hostname, $token]);
$endpoint = $stmt->fetch();

if (!$endpoint) {
    fail(403, 'Invalid hostname or token');
}

$groupId = $endpoint['group_id'];

// --- Cap nhat last_seen + status = ONLINE ---
$pdo->prepare("UPDATE endpoints SET last_seen = NOW(), status = 'ONLINE' WHERE id = ?")
    ->execute([$endpoint['id']]);

// --- Lay ten nhom ---
$groupName = null;
if ($groupId) {
    $stmt = $pdo->prepare("SELECT name FROM groups WHERE id = ?");
    $stmt->execute([$groupId]);
    $groupName = $stmt->fetchColumn() ?: null;
}

$policies = [];

if ($groupId) {
    // --- Lay policy_rules cua nhom nay ---
    $stmt = $pdo->prepare("SELECT id, exit_point_type, state FROM policy_rules WHERE group_id = ?");
    $stmt->execute([$groupId]);
    $policyRows = $stmt->fetchAll();

    foreach ($policyRows as $row) {
        $contentRules = [];

        // Chi can lay content_rules neu state la MONITORED hoac CONTROLLED
        if (in_array($row['state'], ['MONITORED', 'CONTROLLED'])) {
            $stmt2 = $pdo->prepare("
                SELECT cr.id, cr.rule_name, cr.rule_type, cr.pattern, cr.category, cr.severity
                FROM policy_content_rules pcr
                JOIN content_rules cr ON pcr.content_rule_id = cr.id
                WHERE pcr.policy_id = ? AND cr.is_active = 1
            ");
            $stmt2->execute([$row['id']]);
            $contentRules = $stmt2->fetchAll();
        }

        $policies[] = [
            'exit_point_type' => $row['exit_point_type'],
            'state'           => $row['state'],
            'content_rules'   => $contentRules,
        ];
    }
}

// --- Lay USB whitelist (theo nhom hoac ap dung chung group_id IS NULL) ---
$stmt = $pdo->prepare("SELECT serial_number FROM usb_whitelist WHERE group_id = ? OR group_id IS NULL");
$stmt->execute([$groupId]);
$usbWhitelist = array_column($stmt->fetchAll(), 'serial_number');

// --- Lay network blacklist (ap dung chung toan he thong) ---
$stmt = $pdo->query("SELECT target_type, value FROM network_blacklist WHERE is_active = 1");
$networkBlacklist = $stmt->fetchAll();

// --- Tra response ---
echo json_encode([
    'group_name'        => $groupName,
    'policies'          => $policies,
    'usb_whitelist'     => $usbWhitelist,
    'network_blacklist' => $networkBlacklist,
], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
