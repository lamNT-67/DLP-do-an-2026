<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/helpers.php';

// Endpoint duoc coi la OFFLINE neu khong heartbeat qua 5 phut (300s)
$pdo->exec("UPDATE endpoints SET status = 'OFFLINE' WHERE last_seen < (NOW() - INTERVAL 5 MINUTE)");

$totalEndpoints  = $pdo->query("SELECT COUNT(*) FROM endpoints")->fetchColumn();
$onlineEndpoints = $pdo->query("SELECT COUNT(*) FROM endpoints WHERE status = 'ONLINE'")->fetchColumn();
$totalGroups     = $pdo->query("SELECT COUNT(*) FROM groups")->fetchColumn();
$violationsToday = $pdo->query("SELECT COUNT(*) FROM violation_summary WHERE DATE(occurred_at) = CURDATE()")->fetchColumn();

$recentViolations = $pdo->query("
    SELECT v.*, e.hostname, e.username
    FROM violation_summary v
    JOIN endpoints e ON v.endpoint_id = e.id
    ORDER BY v.occurred_at DESC
    LIMIT 10
")->fetchAll();

$byExitPoint = $pdo->query("
    SELECT exit_point_type, COUNT(*) as cnt
    FROM violation_summary
    GROUP BY exit_point_type
    ORDER BY cnt DESC
")->fetchAll();

$pageTitle = 'Dashboard';
$activeMenu = 'dashboard';
require __DIR__ . '/../includes/layout_header.php';
?>

<div class="stats-grid">
    <div class="stat-card">
        <div class="value"><?= (int)$totalEndpoints ?></div>
        <div class="label">Tong so Endpoint</div>
    </div>
    <div class="stat-card">
        <div class="value"><?= (int)$onlineEndpoints ?></div>
        <div class="label">Endpoint dang Online</div>
    </div>
    <div class="stat-card">
        <div class="value"><?= (int)$totalGroups ?></div>
        <div class="label">So Nhom nguoi dung</div>
    </div>
    <div class="stat-card">
        <div class="value"><?= (int)$violationsToday ?></div>
        <div class="label">Vi pham hom nay</div>
    </div>
</div>

<div class="card">
    <h2>Vi pham theo Exit Point</h2>
    <table>
        <thead><tr><th>Exit Point</th><th>So luong</th></tr></thead>
        <tbody>
        <?php if (empty($byExitPoint)): ?>
            <tr><td colspan="2">Chua co du lieu.</td></tr>
        <?php endif; ?>
        <?php foreach ($byExitPoint as $row): ?>
            <tr>
                <td><?= h($row['exit_point_type']) ?></td>
                <td><?= (int)$row['cnt'] ?></td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
</div>

<div class="card">
    <h2>10 vi pham gan nhat</h2>
    <table>
        <thead>
        <tr>
            <th>Thoi gian</th><th>May</th><th>User</th><th>Exit Point</th>
            <th>Hanh dong</th><th>Muc do</th>
        </tr>
        </thead>
        <tbody>
        <?php if (empty($recentViolations)): ?>
            <tr><td colspan="6">Chua co vi pham nao duoc ghi nhan.</td></tr>
        <?php endif; ?>
        <?php foreach ($recentViolations as $v): ?>
            <tr>
                <td><?= h(format_datetime($v['occurred_at'])) ?></td>
                <td><?= h($v['hostname']) ?></td>
                <td><?= h($v['username'] ?? '-') ?></td>
                <td><?= h($v['exit_point_type']) ?></td>
                <td><?= h($v['action_taken']) ?></td>
                <td>
                    <?php if ($v['confidence_score']): ?>
                        <span class="badge <?= severity_badge_class($v['confidence_score']) ?>">
                            <?= h($v['confidence_score']) ?>
                        </span>
                    <?php else: ?>-<?php endif; ?>
                </td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    <p style="margin-top:12px"><a href="violations.php">Xem toan bo nhat ky &rarr;</a></p>
</div>

<?php require __DIR__ . '/../includes/layout_footer.php'; ?>
