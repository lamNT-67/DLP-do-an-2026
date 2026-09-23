<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/helpers.php';

$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'add') {
    $name = trim($_POST['name'] ?? '');
    $description = trim($_POST['description'] ?? '');

    if ($name !== '') {
        try {
            $stmt = $pdo->prepare("INSERT INTO groups (name, description) VALUES (?, ?)");
            $stmt->execute([$name, $description]);
            $message = 'Da them Group moi. Vao Devices de gan thiet bi, vao DLP Policies de tao chinh sach.';
        } catch (PDOException $e) {
            $message = 'Loi: ten Group co the da ton tai.';
        }
    }
}

if (isset($_GET['delete'])) {
    $pdo->prepare("DELETE FROM groups WHERE id = ?")->execute([(int)$_GET['delete']]);
    header('Location: groups.php');
    exit;
}

$groups = $pdo->query("
    SELECT g.*, COUNT(d.id) as device_count
    FROM groups g
    LEFT JOIN devices d ON d.group_id = g.id
    GROUP BY g.id
    ORDER BY g.id
")->fetchAll();

$pageTitle = 'Groups';
$activeMenu = 'groups';
require __DIR__ . '/../includes/layout_header.php';
?>

<?php if ($message): ?>
    <div class="success-msg"><?= h($message) ?></div>
<?php endif; ?>

<div class="card">
    <h2>Them Group moi</h2>
    <form method="POST">
        <input type="hidden" name="action" value="add">
        <div class="form-group">
            <label>Ten Group</label>
            <input type="text" name="name" placeholder="VD: Kinh doanh" required>
        </div>
        <div class="form-group">
            <label>Mo ta</label>
            <input type="text" name="description">
        </div>
        <button type="submit" class="btn btn-primary">Them Group</button>
    </form>
</div>

<div class="card">
    <h2>Danh sach Group (<?= count($groups) ?>)</h2>
    <table>
        <thead><tr><th>ID</th><th>Ten Group</th><th>Mo ta</th><th>So thiet bi</th><th>Hanh dong</th></tr></thead>
        <tbody>
        <?php foreach ($groups as $g): ?>
            <tr>
                <td><?= (int)$g['id'] ?></td>
                <td><?= h($g['name']) ?></td>
                <td><?= h($g['description']) ?></td>
                <td><?= (int)$g['device_count'] ?></td>
                <td>
                    <a href="devices.php?group_id=<?= (int)$g['id'] ?>" class="btn btn-secondary btn-sm">Xem thiet bi</a>
                    <a href="groups.php?delete=<?= (int)$g['id'] ?>" class="btn btn-danger btn-sm"
                       onclick="return confirm('Xoa Group nay?')">Xoa</a>
                </td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
</div>

<?php require __DIR__ . '/../includes/layout_footer.php'; ?>