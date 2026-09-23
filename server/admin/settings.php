<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/helpers.php';

$message = '';
$newKey = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'create_key') {
    $description = trim($_POST['description'] ?? '');
    $key = 'DLP-ENROLL-' . strtoupper(bin2hex(random_bytes(8)));

    $stmt = $pdo->prepare("INSERT INTO enrollment_keys (enrollment_key, description, created_by) VALUES (?, ?, ?)");
    $stmt->execute([$key, $description, current_admin_name()]);
    $message = 'Da tao Enrollment Key moi. Dua key nay vao file config cua Agent khi trien khai.';
    $newKey = $key;
}

if (isset($_GET['toggle'])) {
    $pdo->prepare("UPDATE enrollment_keys SET is_active = NOT is_active WHERE id = ?")->execute([(int)$_GET['toggle']]);
    header('Location: settings.php');
    exit;
}

if (isset($_GET['delete'])) {
    $pdo->prepare("DELETE FROM enrollment_keys WHERE id = ?")->execute([(int)$_GET['delete']]);
    header('Location: settings.php');
    exit;
}

$keys = $pdo->query("
    SELECT ek.*, (SELECT COUNT(*) FROM devices WHERE enrolled_via_key_id = ek.id) as devices_enrolled
    FROM enrollment_keys ek ORDER BY ek.created_at DESC
")->fetchAll();

$pageTitle = 'Settings';
$activeMenu = 'settings';
require __DIR__ . '/../includes/layout_header.php';
?>

<?php if ($message): ?>
    <div class="success-msg">
        <?= h($message) ?>
        <?php if ($newKey): ?><div class="token-box"><?= h($newKey) ?></div><?php endif; ?>
    </div>
<?php endif; ?>

<div class="card">
    <h2>Tao Enrollment Key moi</h2>
    <p style="font-size:13px; color:#616e7c; margin-bottom:14px;">
        Agent dung key nay de tu dang ky voi Server lan dau (goi <code>POST /api/agent_register.php</code>).
        Sau khi dang ky, Agent nhan mot API token rieng va khong can dung lai Enrollment Key nua.
    </p>
    <form method="POST">
        <input type="hidden" name="action" value="create_key">
        <div class="form-group">
            <label>Mo ta (vd: dot trien khai, phong ban)</label>
            <input type="text" name="description" placeholder="VD: Trien khai dot 1 - Kinh doanh">
        </div>
        <button type="submit" class="btn btn-primary">Tao Key</button>
    </form>
</div>

<div class="card">
    <h2>Danh sach Enrollment Keys (<?= count($keys) ?>)</h2>
    <table>
        <thead><tr><th>Key</th><th>Mo ta</th><th>So may da dung</th><th>Trang thai</th><th>Ngay tao</th><th>Hanh dong</th></tr></thead>
        <tbody>
        <?php foreach ($keys as $k): ?>
            <tr>
                <td style="font-family:monospace; font-size:12px;"><?= h($k['enrollment_key']) ?></td>
                <td><?= h($k['description']) ?></td>
                <td><?= (int)$k['devices_enrolled'] ?></td>
                <td><?= $k['is_active'] ? 'Dang bat' : 'Da tat' ?></td>
                <td><?= h(format_datetime($k['created_at'])) ?></td>
                <td>
                    <a href="settings.php?toggle=<?= (int)$k['id'] ?>" class="btn btn-secondary btn-sm">
                        <?= $k['is_active'] ? 'Tat' : 'Bat' ?>
                    </a>
                    <a href="settings.php?delete=<?= (int)$k['id'] ?>" class="btn btn-danger btn-sm"
                       onclick="return confirm('Xoa key nay?')">Xoa</a>
                </td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
</div>

<?php require __DIR__ . '/../includes/layout_footer.php'; ?>