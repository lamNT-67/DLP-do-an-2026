<?php
$host = getenv('DLP_DB_HOST') ?: 'localhost';
$db = getenv('DLP_DB_NAME') ?: 'dlp_system';
$user = getenv('DLP_DB_USER') ?: 'root';
$pass = getenv('DLP_DB_PASSWORD') !== false ? getenv('DLP_DB_PASSWORD') : '';
$charset = 'utf8mb4';
$dsn = "mysql:host=$host;dbname=$db;charset=$charset";
$options = [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES => false,
];
try {
    $pdo = new PDO($dsn, $user, $pass, $options);
} catch (PDOException $e) {
    error_log('[DLP DB] ' . $e->getMessage());
    http_response_code(500);
    if (strpos($_SERVER['REQUEST_URI'] ?? '', '/api/') !== false) {
        header('Content-Type: application/json; charset=utf-8');
        die(json_encode(['error' => 'Database unavailable']));
    }
    die('Loi ket noi database. Vui long kiem tra cau hinh.');
}
