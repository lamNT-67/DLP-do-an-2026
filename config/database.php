<?php
/**
 * Ket noi database dung chung.
 * Sua lai $user/$pass neu XAMPP cua ban dat mat khau MySQL khac mac dinh.
 */

$host = 'localhost';
$db   = 'dlp_system';
$user = 'root';
$pass = '';
$charset = 'utf8mb4';

$dsn = "mysql:host=$host;dbname=$db;charset=$charset";
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
];

try {
    $pdo = new PDO($dsn, $user, $pass, $options);
} catch (PDOException $e) {
    http_response_code(500);
    // Neu goi tu API (JSON), tra loi JSON. Neu tu trang admin, hien loi thuong.
    if (strpos($_SERVER['REQUEST_URI'] ?? '', '/api/') !== false) {
        header('Content-Type: application/json; charset=utf-8');
        die(json_encode(['error' => 'DB connection failed: ' . $e->getMessage()]));
    }
    die('Loi ket noi database: ' . $e->getMessage());
}
