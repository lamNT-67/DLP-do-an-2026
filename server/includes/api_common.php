<?php
declare(strict_types=1);

function api_error(int $status, string $message): void {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['error' => $message], JSON_UNESCAPED_UNICODE);
    exit;
}
function api_method(string $method): void {
    header('Allow: ' . $method);
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== $method) api_error(405, 'Method not allowed');
}
function api_json(): array {
    if (stripos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') !== 0) api_error(415, 'Content-Type must be application/json');
    $raw = file_get_contents('php://input');
    if ($raw === false || strlen($raw) > 65536) api_error(413, 'Request body too large');
    $data = json_decode($raw, true);
    if (!is_array($data) || array_is_list($data)) api_error(400, 'Invalid JSON object');
    return $data;
}
function api_string(array $data, string $key, int $max = 255, bool $required = false): ?string {
    $value = $data[$key] ?? null;
    if ($value === null && !$required) return null;
    if (!is_string($value)) api_error(400, 'Invalid field: ' . $key);
    $value = trim($value);
    if (($required && $value === '') || strlen($value) > $max) api_error(400, 'Invalid field: ' . $key);
    return $value === '' ? null : $value;
}
function api_token(): string {
    $header = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
    if ($header === '' && function_exists('getallheaders')) {
        foreach (getallheaders() as $name => $value) {
            if (strcasecmp($name, 'Authorization') === 0) { $header = $value; break; }
        }
    }
    if (!preg_match('/^Bearer\s+([A-Za-z0-9._~-]+)$/i', trim($header), $match)) api_error(401, 'Missing or invalid Bearer token');
    return $match[1];
}
function api_device(PDO $pdo, string $token, ?string $hostname = null): array {
    $stmt = $pdo->prepare('SELECT * FROM devices WHERE api_token = ?');
    $stmt->execute([$token]);
    $device = $stmt->fetch();
    if (!$device || ($hostname !== null && $device['hostname'] !== $hostname)) api_error(401, 'Invalid device credentials');
    return $device;
}
function api_db_error(Throwable $e): void {
    error_log('[DLP API] ' . $e->getMessage());
    api_error(500, 'Internal server error');
}
