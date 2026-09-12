<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/helpers.php';

// --- Bo loc ---
$filterExitPoint = $_GET['exit_point_type'] ?? '';
$filterAction = $_GET['action_taken'] ?? '';
$filterHostname = trim($_GET['hostname'] ?? '');

$where = [];
$params = [];

if ($filterExitPoint !== '') {
    $where[] = 'v.exit_point_type = ?';
    $params[] = $filterExitPoint;
}
if ($filterAction !== '') {
    $where[] = 'v.action_taken = ?';
    $params[] = $filterAction;
}
if ($filterHostname !== '') {
    $where[] = 'e.hostname LIKE ?';
    $params[] = '%' . $filterHostname . '%';
}

$whereSql = $where ? ('WHERE ' . implode(' AND ', $where)) : '';

$stmt = $pdo->prepare("
    SELECT v.*, e.hostname, e.username
    FROM violation_summary v
    JOIN endpoints e ON v.endpoint_id = e.id
    $whereSql
    ORDER BY v.occurred_at DESC
    LIMIT 200
");
$stmt->execute($params);
$violations = $stmt->fetchAll();

$pageTitle = 'Nhat ky vi pham';
$activeMenu = 'violations';
require __DIR__ . '/../includes/layout_header.php';
?>

<div class="card">
    <h2>Bo loc</h2>
    <form method="GET" style="display:flex; gap:12px; align-items:end; flex-wrap:wrap;">
        <div class="form-group" style="margin-bottom:0;">
            <label>Exit Point</label>
            <select name="exit_point_type">
                <option value="">-- Tat ca --</option>
                <?php foreach (['USB','CLIPBOARD','NETWORK_WEB','NETWORK_SCP_SFTP','NETWORK_FTP','RDP'] as $ep): ?>
                    <option value="<?= $ep ?>" <?= $filterExitPoint === $ep ? 'selected' : '' ?>><?= $ep ?></option>
                <?php endforeach; ?>
            </select>
        </div>
        <div class="form-group" style="margin-bottom:0;">
            <label>Hanh dong</label>
            <select name="action_taken">
                <option value="">-- Tat ca --</option>
                <?php foreach (['ALLOWED','LOGGED','BLOCKED_DELETE','BLOCKED_FIREWALL','BLOCKED_KILL'] as $a): ?>
                    <option value="<?= $a ?>" <?= $filterAction === $a ? 'selected' : '' ?>><?= $a ?></option>
                <?php endforeach; ?>
            </select>
        </div>
        <div class="form-group" style="margin-bottom:0;">
            <label>Hostname</label>
            <input type="text" name="hostname" value="<?= h($filterHostname) ?>" placeholder="Tim theo ten may">
        </div>
        <button type="submit" class="btn btn-primary">Loc</button>
        <a href="violations.php" class="btn btn-secondary">Xoa loc</a>
    </form>
</div>

<div class="card">
    <h2>Ket qua (<?= count($violations) ?> ban ghi, toi da 200)</h2>
    <table>
        <thead>
        <tr>
            <th>Thoi gian</th><th>May</th><th>Exit Point</th><th>Hanh dong</th>
            <th>File</th><th>Rule khop</th><th>Muc do</th><th>Dich den</th><th>Tien trinh</th>
        </tr>
        </thead>
        <tbody>
        <?php if (empty($violations)): ?>
            <tr><td colspan="9">Khong co ban ghi nao khop bo loc.</td></tr>
        <?php endif; ?>
        <?php foreach ($violations as $v): ?>
            <tr>
                <td><?= h(format_datetime($v['occurred_at'])) ?></td>
                <td><?= h($v['hostname']) ?> <?= $v['username'] ? '('.h($v['username']).')' : '' ?></td>
                <td><?= h($v['exit_point_type']) ?></td>
                <td><?= h($v['action_taken']) ?></td>
                <td style="max-width:200px; word-break:break-all; font-size:12px;"><?= h($v['file_path'] ?? '-') ?></td>
                <td style="font-size:12px;"><?= h($v['matched_rule_ids'] ?? '-') ?></td>
                <td>
                    <?php if ($v['confidence_score']): ?>
                        <span class="badge <?= severity_badge_class($v['confidence_score']) ?>"><?= h($v['confidence_score']) ?></span>
                    <?php else: ?>-<?php endif; ?>
                </td>
                <td style="font-size:12px;"><?= h($v['destination_value'] ?? '-') ?></td>
                <td style="font-size:12px;"><?= h($v['process_name'] ?? '-') ?></td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
</div>

<?php require __DIR__ . '/../includes/layout_footer.php'; ?>
