<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/helpers.php';

$message = '';

// --- Xu ly them nhom moi ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'add') {
    $name = trim($_POST['name'] ?? '');
    $description = trim($_POST['description'] ?? '');

    if ($name !== '') {
        try {
            $stmt = $pdo->prepare("INSERT INTO groups (name, description) VALUES (?, ?)");
            $stmt->execute([$name, $description]);

            // Tao san 4 dong policy_rules mac dinh (state = MONITORED) cho nhom moi,
            // de trang policy.php co san du lieu de sua ngay, khong bi thieu dong.
            $newGroupId = $pdo->lastInsertId();
            $exitPoints = ['USB', 'CLIPBOARD', 'NETWORK_WEB', 'NETWORK_SCP_SFTP', 'NETWORK_FTP', 'RDP'];
            $insertPolicy = $pdo->prepare("INSERT INTO policy_rules (group_id, exit_point_type, state, updated_by) VALUES (?, ?, 'MONITORED', ?)");
            foreach ($exitPoints as $ep) {
                $insertPolicy->execute([$newGroupId, $ep, current_admin_name()]);
            }

            $message = 'Da them nhom moi.';
        } catch (PDOException $e) {
            $message = 'Loi: ten nhom co the da ton tai.';
        }
    }
}

// --- Xu ly xoa nhom ---
if (isset($_GET['delete'])) {
    $pdo->prepare("DELETE FROM groups WHERE id = ?")->execute([(int)$_GET['delete']]);
    header('Location: groups.php');
    exit;
}

$groups = $pdo->query("
    SELECT g.*, COUNT(e.id) as endpoint_count
    FROM groups g
    LEFT JOIN endpoints e ON e.group_id = g.id
    GROUP BY g.id
    ORDER BY g.id
")->fetchAll();

$pageTitle = 'Nhom nguoi dung';
$activeMenu = 'groups';
require __DIR__ . '/../includes/layout_header.php';
?>

<?php if ($message): ?>
    <div class="success-msg"><?= h($message) ?></div>
<?php endif; ?>

<div class="card">
    <h2>Them nhom moi</h2>
    <form method="POST">
        <input type="hidden" name="action" value="add">
        <div class="form-group">
            <label>Ten nhom</label>
            <input type="text" name="name" placeholder="VD: Kinh doanh" required>
        </div>
        <div class="form-group">
            <label>Mo ta</label>
            <input type="text" name="description" placeholder="Mo ta ngan gon">
        </div>
        <button type="submit" class="btn btn-primary">Them nhom</button>
    </form>
</div>

<div class="card">
    <h2>Danh sach nhom (<?= count($groups) ?>)</h2>
    <table>
        <thead>
        <tr><th>ID</th><th>Ten nhom</th><th>Mo ta</th><th>So endpoint</th><th>Hanh dong</th></tr>
        </thead>
        <tbody>
        <?php foreach ($groups as $g): ?>
            <tr>
                <td><?= (int)$g['id'] ?></td>
                <td><?= h($g['name']) ?></td>
                <td><?= h($g['description']) ?></td>
                <td><?= (int)$g['endpoint_count'] ?></td>
                <td>
                    <a href="policy.php?group_id=<?= (int)$g['id'] ?>" class="btn btn-secondary btn-sm">Cau hinh Policy</a>
                    <a href="groups.php?delete=<?= (int)$g['id'] ?>" class="btn btn-danger btn-sm"
                       onclick="return confirm('Xoa nhom nay? Toan bo policy va endpoint gan voi nhom se bi anh huong.')">Xoa</a>
                </td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
</div>

<?php require __DIR__ . '/../includes/layout_footer.php'; ?>
