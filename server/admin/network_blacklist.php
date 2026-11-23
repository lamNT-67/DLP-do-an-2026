<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/helpers.php';

$message = '';
$error = '';
$allowedTargetTypes = ['DOMAIN', 'IP', 'PORT', 'PROCESS'];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'add') {
    $targetType = strtoupper(trim($_POST['target_type'] ?? 'DOMAIN'));
    $value = trim($_POST['value'] ?? '');
    $description = trim($_POST['description'] ?? '');

    if (!in_array($targetType, $allowedTargetTypes, true)) {
        $error = 'Loai blacklist khong hop le.';
    } elseif ($value === '') {
        $error = 'Vui long nhap gia tri.';
    } elseif ($targetType === 'PROCESS' && !preg_match('/^[A-Za-z0-9_.-]+(?:\.exe)?$/i', $value)) {
        $error = 'Ten process khong hop le. Vi du: curl.exe';
    } else {
        $stmt = $pdo->prepare("INSERT INTO network_blacklist (target_type, value, description) VALUES (?, ?, ?)");
        $stmt->execute([$targetType, $value, $description]);
        $message = 'Da them vao blacklist.';
    }
}

if (isset($_GET['toggle'])) {
    $pdo->prepare("UPDATE network_blacklist SET is_active = NOT is_active WHERE id = ?")->execute([(int)$_GET['toggle']]);
    header('Location: network_blacklist.php');
    exit;
}

if (isset($_GET['delete'])) {
    $pdo->prepare("DELETE FROM network_blacklist WHERE id = ?")->execute([(int)$_GET['delete']]);
    header('Location: network_blacklist.php');
    exit;
}

$items = $pdo->query("SELECT * FROM network_blacklist ORDER BY target_type, value")->fetchAll();

$pageTitle = 'Network Blacklist';
$activeMenu = 'network_blacklist';
require __DIR__ . '/../includes/layout_header.php';
?>

<?php if ($message): ?>
    <div class="success-msg"><?= h($message) ?></div>
<?php endif; ?>
<?php if ($error): ?>
    <div class="alert alert-error"><?= h($error) ?></div>
<?php endif; ?>

<div class="card">
    <h2>Them Domain/IP/Port/Process vao Blacklist</h2>
    <p class="hint">PROCESS la ten tien trinh can Agent xu ly, vi du curl.exe. Muc nay chi gui cau hinh den Agent; can cap nhat Agent de thuc hien chan tien trinh. Blacklist dang ap dung global cho cac Agent nhan policy.</p>
    <form method="POST">
        <input type="hidden" name="action" value="add">
        <div class="form-group">
            <label>Loai</label>
            <select name="target_type">
                <option value="DOMAIN">DOMAIN</option>
                <option value="IP">IP</option>
                <option value="PORT">PORT</option>
                <option value="PROCESS">PROCESS (ten tien trinh)</option>
            </select>
        </div>
        <div class="form-group">
            <label>Gia tri</label>
            <input type="text" name="value" placeholder="curl.exe / example.com / 192.0.2.10 / 22" required>
        </div>
        <div class="form-group">
            <label>Mo ta</label>
            <input type="text" name="description">
        </div>
        <button type="submit" class="btn btn-primary">Them vao Blacklist</button>
    </form>
</div>

<div class="card">
    <h2>Danh sach Blacklist (<?= count($items) ?>)</h2>
    <table>
        <thead><tr><th>Loai</th><th>Gia tri</th><th>Mo ta</th><th>Trang thai</th><th>Hanh dong</th></tr></thead>
        <tbody>
        <?php foreach ($items as $i): ?>
            <tr>
                <td><?= h($i['target_type']) ?></td>
                <td><?= h($i['value']) ?></td>
                <td><?= h($i['description']) ?></td>
                <td><?= $i['is_active'] ? 'Dang bat' : 'Da tat' ?></td>
                <td>
                    <a href="network_blacklist.php?toggle=<?= (int)$i['id'] ?>" class="btn btn-secondary btn-sm"><?= $i['is_active'] ? 'Tat' : 'Bat' ?></a>
                    <a href="network_blacklist.php?delete=<?= (int)$i['id'] ?>" class="btn btn-danger btn-sm" onclick="return confirm('Xoa?')">Xoa</a>
                </td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
</div>

<?php require __DIR__ . '/../includes/layout_footer.php'; ?>
