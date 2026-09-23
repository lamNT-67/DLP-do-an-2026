<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/helpers.php';

$pdo->exec("UPDATE devices SET status = 'OFFLINE' WHERE last_seen < (NOW() - INTERVAL 5 MINUTE)");

$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'assign_group') {
    $deviceId = (int)$_POST['device_id'];
    $groupId = $_POST['group_id'] === '' ? null : (int)$_POST['group_id'];

    $pdo->prepare("UPDATE devices SET group_id = ? WHERE id = ?")->execute([$groupId, $deviceId]);
    $message = 'Da cap nhat Group cho thiet bi.';
}

if (isset($_GET['delete'])) {
    $pdo->prepare("DELETE FROM devices WHERE id = ?")->execute([(int)$_GET['delete']]);
    header('Location: devices.php');
    exit;
}

$groups = $pdo->query("SELECT id, name FROM groups ORDER BY name")->fetchAll();

$filterGroup = $_GET['group_id'] ?? '';
$where = '';
$params = [];
if ($filterGroup === 'unassigned') {
    $where = 'WHERE d.group_id IS NULL';
} elseif ($filterGroup !== '') {
    $where = 'WHERE d.group_id = ?';
    $params[] = (int)$filterGroup;
}

$stmt = $pdo->prepare("
    SELECT d.*, g.name as group_name
    FROM devices d
    LEFT JOIN groups g ON d.group_id = g.id
    $where
    ORDER BY d.last_seen DESC
");
$stmt->execute($params);
$devices = $stmt->fetchAll();

$pageTitle = 'Devices';
$activeMenu = 'devices';
require __DIR__ . '/../includes/layout_header.php';
?>

<?php if ($message): ?>
    <div class="success-msg"><?= h($message) ?></div>
<?php endif; ?>

<div class="card">
    <p style="font-size:13px; color:#616e7c;">
        Thiet bi tu dong xuat hien tai day khi Agent cai dat va goi API dang ky lan dau
        (dung Enrollment Key — xem trang <a href="settings.php">Settings</a>). Khong co thao tac them may thu cong.
    </p>
</div>

<div class="card">
    <h2>Loc theo Group</h2>
    <form method="GET" style="max-width:300px;">
        <select name="group_id" onchange="this.form.submit()">
            <option value="">-- Tat ca --</option>
            <option value="unassigned" <?= $filterGroup === 'unassigned' ? 'selected' : '' ?>>Unassigned (chua gan)</option>
            <?php foreach ($groups as $g): ?>
                <option value="<?= (int)$g['id'] ?>" <?= (string)$filterGroup === (string)$g['id'] ? 'selected' : '' ?>>
                    <?= h($g['name']) ?>
                </option>
            <?php endforeach; ?>
        </select>
    </form>
</div>

<div class="card">
    <h2>Danh sach Devices (<?= count($devices) ?>)</h2>
    <table>
        <thead>
        <tr>
            <th>Status</th><th>Hostname</th><th>IP</th><th>OS</th><th>User</th>
            <th>Group</th><th>Agent Ver.</th><th>Lan cuoi hoat dong</th><th>Hanh dong</th>
        </tr>
        </thead>
        <tbody>
        <?php if (empty($devices)): ?>
            <tr><td colspan="9">Chua co thiet bi nao dang ky.</td></tr>
        <?php endif; ?>
        <?php foreach ($devices as $d): ?>
            <tr>
                <td><span class="dot <?= status_dot_class($d['status']) ?>"></span><?= h($d['status']) ?></td>
                <td><?= h($d['hostname']) ?></td>
                <td><?= h($d['ip_address'] ?? '-') ?></td>
                <td><?= h($d['os_info'] ?? '-') ?></td>
                <td><?= h($d['username'] ?? '-') ?></td>
                <td>
                    <form method="POST" style="display:flex; gap:6px;">
                        <input type="hidden" name="action" value="assign_group">
                        <input type="hidden" name="device_id" value="<?= (int)$d['id'] ?>">
                        <select name="group_id" onchange="this.form.submit()">
                            <option value="">-- Unassigned --</option>
                            <?php foreach ($groups as $g): ?>
                                <option value="<?= (int)$g['id'] ?>" <?= $d['group_id'] == $g['id'] ? 'selected' : '' ?>>
                                    <?= h($g['name']) ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </form>
                </td>
                <td><?= h($d['agent_version'] ?? '-') ?></td>
                <td><?= h(format_datetime($d['last_seen'])) ?></td>
                <td>
                    <a href="devices.php?delete=<?= (int)$d['id'] ?>" class="btn btn-danger btn-sm"
                       onclick="return confirm('Xoa thiet bi nay khoi he thong? Agent se can enrollment key de dang ky lai.')">Xoa</a>
                </td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
</div>

<?php require __DIR__ . '/../includes/layout_footer.php'; ?>