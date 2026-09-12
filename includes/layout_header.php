<?php
/**
 * Include file nay SAU khi da: session_start(), require auth.php,
 * va dat bien $pageTitle + $activeMenu truoc do.
 *
 * Vi du dau trang:
 *   $pageTitle = 'Dashboard';
 *   $activeMenu = 'dashboard';
 *   require '../includes/layout_header.php';
 */
$activeMenu = $activeMenu ?? '';
$menuItems = [
    'dashboard'         => ['label' => 'Dashboard',         'href' => 'dashboard.php'],
    'groups'            => ['label' => 'Nhom nguoi dung',    'href' => 'groups.php'],
    'policy'            => ['label' => 'Policy Exit Point',  'href' => 'policy.php'],
    'content_rules'     => ['label' => 'Content Rules',      'href' => 'content_rules.php'],
    'usb_whitelist'     => ['label' => 'USB Whitelist',      'href' => 'usb_whitelist.php'],
    'network_blacklist' => ['label' => 'Network Blacklist',  'href' => 'network_blacklist.php'],
    'endpoints'         => ['label' => 'Endpoints',          'href' => 'endpoints.php'],
    'violations'        => ['label' => 'Nhat ky vi pham',    'href' => 'violations.php'],
];
?>
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <title><?= h($pageTitle ?? 'DLP Admin') ?> - DLP Management Server</title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>
<div class="layout">
    <div class="sidebar">
        <h2>DLP Management</h2>
        <nav>
            <?php foreach ($menuItems as $key => $item): ?>
                <a href="<?= h($item['href']) ?>" class="<?= $activeMenu === $key ? 'active' : '' ?>">
                    <?= h($item['label']) ?>
                </a>
            <?php endforeach; ?>
            <div class="logout">
                <a href="logout.php">Dang xuat</a>
            </div>
        </nav>
    </div>
    <div class="main">
        <div class="topbar">
            <h1><?= h($pageTitle ?? '') ?></h1>
            <div class="admin-name">Xin chao, <strong><?= h(current_admin_name()) ?></strong></div>
        </div>
