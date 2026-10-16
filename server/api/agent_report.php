<?php
declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/api_common.php';
api_method('POST');
$token = api_token();
$data = api_json();
$hostname = api_string($data, 'hostname', 100, true);
$exit = api_string($data, 'exit_point_type', 40, true);
$action = api_string($data, 'action_taken', 40, true);
$occurred = api_string($data, 'occurred_at', 40, true);
if (!in_array($exit, ['USB','CLIPBOARD','NETWORK_WEB','NETWORK_SCP_SFTP','NETWORK_FTP','RDP','SCREEN_CAPTURE'], true)) api_error(400, 'Invalid exit_point_type');
if (!in_array($action, ['ALLOWED','LOGGED','BLOCKED_DELETE','BLOCKED_FIREWALL','BLOCKED_KILL','BLOCKED_PROXY'], true)) api_error(400, 'Invalid action_taken');
try {
    $dt = new DateTimeImmutable($occurred);
    if (!preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/', $occurred)) throw new Exception('invalid format');
    $utc = $dt->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s');
} catch (Throwable $e) { api_error(400, 'occurred_at must be ISO 8601 with timezone'); }
$policyId = $data['policy_id'] ?? null;
if ($policyId !== null && (!is_int($policyId) || $policyId <= 0)) api_error(400, 'Invalid policy_id');
$hash = api_string($data, 'file_hash_sha256', 64);
if ($hash !== null && !preg_match('/^[a-fA-F0-9]{64}$/', $hash)) api_error(400, 'Invalid SHA-256');
$confidence = api_string($data, 'confidence_score', 10);
if ($confidence !== null && !in_array($confidence, ['LOW','MEDIUM','HIGH','CRITICAL'], true)) api_error(400, 'Invalid confidence_score');
$rules = $data['matched_rule_ids'] ?? null;
if (is_array($rules)) {
    foreach ($rules as $id) if (!is_int($id) || $id <= 0) api_error(400, 'Invalid matched_rule_ids');
    $rules = implode(',', $rules);
} elseif ($rules !== null && (!is_string($rules) || !preg_match('/^\d+(,\d+)*$/', $rules))) api_error(400, 'Invalid matched_rule_ids');
if ($rules !== null && strlen($rules) > 255) api_error(400, 'matched_rule_ids too long');
$file = api_string($data, 'file_path', 500);
$dest = api_string($data, 'destination_value', 255);
$process = api_string($data, 'process_name', 100);
try {
    $device = api_device($pdo, $token, $hostname);
    if ($policyId !== null) {
        $stmt = $pdo->prepare("SELECT 1 FROM dlp_policies p LEFT JOIN dlp_policy_devices pd ON pd.policy_id=p.id AND pd.device_id=? WHERE p.id=? AND p.is_active=1 AND ((p.target_type='GROUP' AND p.target_group_id=?) OR (p.target_type='DEVICE' AND pd.device_id IS NOT NULL)) LIMIT 1");
        $stmt->execute([$device['id'], $policyId, $device['group_id']]);
        if (!$stmt->fetchColumn()) api_error(400, 'policy_id is not assigned to this device');
    }
    $stmt = $pdo->prepare('INSERT INTO logs (device_id,policy_id,exit_point_type,action_taken,file_path,file_hash_sha256,matched_rule_ids,confidence_score,destination_value,process_name,occurred_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)');
    $stmt->execute([$device['id'], $policyId, $exit, $action, $file, $hash, $rules, $confidence, $dest, $process, $utc]);
    http_response_code(201);
    echo json_encode(['status'=>'ok', 'id'=>(int)$pdo->lastInsertId()]);
} catch (PDOException $e) { api_db_error($e); }
