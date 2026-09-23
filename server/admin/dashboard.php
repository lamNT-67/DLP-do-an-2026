<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/helpers.php';

$pdo->exec("UPDATE devices SET status = 'OFFLINE' WHERE last_seen < (NOW() - INTERVAL 5 MINUTE)");

$totalDevices    = $pdo->query("SELECT COUNT(*) FROM devices")->fetchColumn();
$onlineDevices   = $pdo->query("SELECT COUNT(*) FROM devices WHERE status = 'ONLINE'")->fetchColumn();
$unassignedCount = $pdo->query("SELECT COUNT(*) FROM devices WHERE group_id IS NULL")->fetchColumn();
$logsToday       = $pdo->query("SELECT COUNT(*) FROM logs WHERE DATE(occurred_at) = CURDATE()")->fetchColumn();

$recentLogs = $pdo->query("
    SELECT l.*, d.hostname, d.username
    FROM logs l
    JOIN devices d ON l.device_id = d.id
    ORDER BY l.occurred_at DESC
    LIMIT 10
")->fetchAll();

$byExitPoint = $pdo->query("
    SELECT exit_point_type, COUNT(*) as cnt FROM logs GROUP BY exit_point_type ORDER BY cnt DESC
")->fetchAll();

$pageTitle = 'Dashboard';
$activeMenu = 'dashboard';
require __DIR__ . '/../includes/layout_header.php';
?>

<div class="stats-grid">
    <div class="stat-card">
        <div class="value"><?= (int)$totalDevices ?></div>
        <div class="label">Tong so Devices</div>
    </div>
    <div class="stat-card">
        <div class="value"><?= (int)$onlineDevices ?></div>
        <div class="label">Devices Online</div>
    </div>
    <div class="stat-card">
        <div class="value"><?= (int)$unassignedCount ?></div>
        <div class="label">Chua gan Group (Unassigned)</div>
    </div>
    <div class="stat-card">
        <div class="value"><?= (int)$logsToday ?></div>
        <div class="label">Su kien hom nay</div>
    </div>
</div>

<?php if ($unassignedCount > 0): ?>
<div class="card" style="border-left:4px solid #966b00;">
    <p>Co <strong><?= (int)$unassignedCount ?></strong> thiet bi moi tu dang ky chua duoc gan Group -
    <a href="devices.php">vao Devices de gan ngay</a> (Policy chi ap dung sau khi da gan Group).</p>
</div>
<?php endif; ?>

<div class="card">
    <h2>Su kien theo Exit Point</h2>
    <table>
        <thead><tr><th>Exit Point</th><th>So luong</th></tr></thead>
        <tbody>
        <?php if (empty($byExitPoint)): ?>
            <tr><td colspan="2">Chua co du lieu.</td></tr>
        <?php endif; ?>
        <?php foreach ($byExitPoint as $row): ?>
            <tr><td><?= h($row['exit_point_type']) ?></td><td><?= (int)$row['cnt'] ?></td></tr>
        <?php endforeach; ?>
        </tbody>
    </table>
</div>

<div class="card">
    <h2>10 su kien gan nhat</h2>
    <table>
        <thead><tr><th>Thoi gian</th><th>May</th><th>Exit Point</th><th>Hanh dong</th><th>Muc do</th></tr></thead>
        <tbody>
        <?php if (empty($recentLogs)): ?>
            <tr><td colspan="5">Chua co du lieu.</td></tr>
        <?php endif; ?>
        <?php foreach ($recentLogs as $l): ?>
            <tr>
                <td><?= h(format_datetime($l['occurred_at'])) ?></td>
                <td><?= h($l['hostname']) ?></td>
                <td><?= h($l['exit_point_type']) ?></td>
                <td><?= h($l['action_taken']) ?></td>
                <td><?php if ($l['confidence_score']): ?>
                    <span class="badge <?= severity_badge_class($l['confidence_score']) ?>"><?= h($l['confidence_score']) ?></span>
                <?php else: ?>-<?php endif; ?></td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    <p style="margin-top:12px"><a href="logs.php">Xem toan bo Logs &rarr;</a></p>
</div>

<?php require __DIR__ . '/../includes/layout_footer.php'; ?>