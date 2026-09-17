<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/helpers.php';

$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'add') {
    $targetType = $_POST['target_type'] ?? 'DOMAIN';
    $value = trim($_POST['value'] ?? '');
    $description = trim($_POST['description'] ?? '');

    if ($value !== '') {
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

<div class="card">
    <h2>Them Domain/IP/Port vao Blacklist</h2>
    <p style="font-size:13px; color:#616e7c; margin-bottom:14px;">
        Ap dung chung cho toan he thong (khong theo tung nhom) - dung cho exit point Network (Bai toan 2).
    </p>
    <form method="POST">
        <input type="hidden" name="action" value="add">
        <div class="form-group">
            <label>Loai</label>
            <select name="target_type">
                <option value="DOMAIN">DOMAIN</option>
                <option value="IP">IP</option>
                <option value="PORT">PORT</option>
            </select>
        </div>
        <div class="form-group">
            <label>Gia tri</label>
            <input type="text" name="value" placeholder="VD: drive.google.com hoac 22" required>
        </div>
        <div class="form-group">
            <label>Mo ta</label>
            <input type="text" name="description" placeholder="VD: Google Drive upload">
        </div>
        <button type="submit" class="btn btn-primary">Them vao Blacklist</button>
    </form>
</div>

<div class="card">
    <h2>Danh sach Blacklist (<?= count($items) ?>)</h2>
    <table>
        <thead><tr><th>Loai</th><th>Gia tri</th><th>Mo ta</th><th>Trang thai</th><th>Hanh dong</th></tr></thead>
        <tbody>
        <?php if (empty($items)): ?>
            <tr><td colspan="5">Chua co du lieu.</td></tr>
        <?php endif; ?>
        <?php foreach ($items as $i): ?>
            <tr>
                <td><?= h($i['target_type']) ?></td>
                <td><?= h($i['value']) ?></td>
                <td><?= h($i['description']) ?></td>
                <td><?= $i['is_active'] ? 'Dang bat' : 'Da tat' ?></td>
                <td>
                    <a href="network_blacklist.php?toggle=<?= (int)$i['id'] ?>" class="btn btn-secondary btn-sm">
                        <?= $i['is_active'] ? 'Tat' : 'Bat' ?>
                    </a>
                    <a href="network_blacklist.php?delete=<?= (int)$i['id'] ?>" class="btn btn-danger btn-sm"
                       onclick="return confirm('Xoa muc nay?')">Xoa</a>
                </td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
</div>

<?php require __DIR__ . '/../includes/layout_footer.php'; ?>
