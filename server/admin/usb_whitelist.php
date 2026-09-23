<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/helpers.php';

$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'add') {
    $serial = trim($_POST['serial_number'] ?? '');
    $description = trim($_POST['description'] ?? '');
    $groupId = $_POST['group_id'] === '' ? null : (int)$_POST['group_id'];

    if ($serial !== '') {
        try {
            $stmt = $pdo->prepare("INSERT INTO usb_whitelist (serial_number, description, group_id, added_by) VALUES (?, ?, ?, ?)");
            $stmt->execute([$serial, $description, $groupId, current_admin_name()]);
            $message = 'Da them thiet bi vao whitelist.';
        } catch (PDOException $e) {
            $message = 'Loi: Serial number nay co the da ton tai.';
        }
    }
}

if (isset($_GET['delete'])) {
    $pdo->prepare("DELETE FROM usb_whitelist WHERE id = ?")->execute([(int)$_GET['delete']]);
    header('Location: usb_whitelist.php');
    exit;
}

$groups = $pdo->query("SELECT id, name FROM groups ORDER BY name")->fetchAll();

$items = $pdo->query("
    SELECT u.*, g.name as group_name FROM usb_whitelist u
    LEFT JOIN groups g ON u.group_id = g.id ORDER BY u.added_at DESC
")->fetchAll();

$pageTitle = 'USB Whitelist';
$activeMenu = 'usb_whitelist';
require __DIR__ . '/../includes/layout_header.php';
?>

<?php if ($message): ?>
    <div class="success-msg"><?= h($message) ?></div>
<?php endif; ?>

<div class="card">
    <h2>Them thiet bi USB vao Whitelist</h2>
    <form method="POST">
        <input type="hidden" name="action" value="add">
        <div class="form-group">
            <label>Serial Number</label>
            <input type="text" name="serial_number" required>
        </div>
        <div class="form-group">
            <label>Mo ta</label>
            <input type="text" name="description">
        </div>
        <div class="form-group">
            <label>Ap dung cho Group (de trong = toan bo)</label>
            <select name="group_id">
                <option value="">-- Toan bo --</option>
                <?php foreach ($groups as $g): ?>
                    <option value="<?= (int)$g['id'] ?>"><?= h($g['name']) ?></option>
                <?php endforeach; ?>
            </select>
        </div>
        <button type="submit" class="btn btn-primary">Them vao Whitelist</button>
    </form>
</div>

<div class="card">
    <h2>Danh sach Whitelist (<?= count($items) ?>)</h2>
    <table>
        <thead><tr><th>Serial Number</th><th>Mo ta</th><th>Ap dung cho</th><th>Nguoi them</th><th>Ngay them</th><th>Hanh dong</th></tr></thead>
        <tbody>
        <?php if (empty($items)): ?>
            <tr><td colspan="6">Chua co thiet bi nao.</td></tr>
        <?php endif; ?>
        <?php foreach ($items as $i): ?>
            <tr>
                <td><?= h($i['serial_number']) ?></td>
                <td><?= h($i['description']) ?></td>
                <td><?= h($i['group_name'] ?? 'Toan bo') ?></td>
                <td><?= h($i['added_by']) ?></td>
                <td><?= h(format_datetime($i['added_at'])) ?></td>
                <td><a href="usb_whitelist.php?delete=<?= (int)$i['id'] ?>" class="btn btn-danger btn-sm" onclick="return confirm('Go khoi whitelist?')">Xoa</a></td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
</div>

<?php require __DIR__ . '/../includes/layout_footer.php'; ?>