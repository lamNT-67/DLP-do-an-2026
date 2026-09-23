<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/helpers.php';

$filterExitPoint = $_GET['exit_point_type'] ?? '';
$filterAction = $_GET['action_taken'] ?? '';
$filterHostname = trim($_GET['hostname'] ?? '');

$where = [];
$params = [];

if ($filterExitPoint !== '') { $where[] = 'l.exit_point_type = ?'; $params[] = $filterExitPoint; }
if ($filterAction !== '')    { $where[] = 'l.action_taken = ?';    $params[] = $filterAction; }
if ($filterHostname !== '')  { $where[] = 'd.hostname LIKE ?';     $params[] = '%' . $filterHostname . '%'; }

$whereSql = $where ? ('WHERE ' . implode(' AND ', $where)) : '';

$stmt = $pdo->prepare("
    SELECT l.*, d.hostname, d.username
    FROM logs l
    JOIN devices d ON l.device_id = d.id
    $whereSql
    ORDER BY l.occurred_at DESC
    LIMIT 200
");
$stmt->execute($params);
$logs = $stmt->fetchAll();

$pageTitle = 'Logs';
$activeMenu = 'logs';
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
            <input type="text" name="hostname" value="<?= h($filterHostname) ?>">
        </div>
        <button type="submit" class="btn btn-primary">Loc</button>
        <a href="logs.php" class="btn btn-secondary">Xoa loc</a>
    </form>
</div>

<div class="card">
    <h2>Ket qua (<?= count($logs) ?> ban ghi, toi da 200)</h2>
    <table>
        <thead>
        <tr>
            <th>Thoi gian</th><th>May</th><th>Exit Point</th><th>Hanh dong</th>
            <th>File</th><th>Rule khop</th><th>Muc do</th><th>Dich den</th><th>Tien trinh</th>
        </tr>
        </thead>
        <tbody>
        <?php if (empty($logs)): ?>
            <tr><td colspan="9">Khong co ban ghi nao khop bo loc.</td></tr>
        <?php endif; ?>
        <?php foreach ($logs as $l): ?>
            <tr>
                <td><?= h(format_datetime($l['occurred_at'])) ?></td>
                <td><?= h($l['hostname']) ?> <?= $l['username'] ? '('.h($l['username']).')' : '' ?></td>
                <td><?= h($l['exit_point_type']) ?></td>
                <td><?= h($l['action_taken']) ?></td>
                <td style="max-width:200px; word-break:break-all; font-size:12px;"><?= h($l['file_path'] ?? '-') ?></td>
                <td style="font-size:12px;"><?= h($l['matched_rule_ids'] ?? '-') ?></td>
                <td><?php if ($l['confidence_score']): ?>
                    <span class="badge <?= severity_badge_class($l['confidence_score']) ?>"><?= h($l['confidence_score']) ?></span>
                <?php else: ?>-<?php endif; ?></td>
                <td style="font-size:12px;"><?= h($l['destination_value'] ?? '-') ?></td>
                <td style="font-size:12px;"><?= h($l['process_name'] ?? '-') ?></td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
</div>

<?php require __DIR__ . '/../includes/layout_footer.php'; ?>