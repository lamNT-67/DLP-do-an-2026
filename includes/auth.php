<?php
/**
 * Include file nay o dau moi trang trong /admin/ (tru login.php)
 * de bat buoc phai dang nhap moi xem duoc.
 */
session_start();

if (!isset($_SESSION['admin_id'])) {
    header('Location: login.php');
    exit;
}

function current_admin_name() {
    return $_SESSION['admin_full_name'] ?? $_SESSION['admin_username'] ?? 'Admin';
}

function current_admin_role() {
    return $_SESSION['admin_role'] ?? 'VIEWER';
}
