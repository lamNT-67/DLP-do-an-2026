<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/helpers.php';

$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'add') {
    $extension = strtolower(trim($_POST['extension'] ?? '', ". \t"));
    $category = $_POST['category'] ?? 'OTHER';
    $alwaysBlock = isset($_POST['always_block']) ? 1 : 0;
    $description = trim($_POST['description'] ?? '');

    if ($extension !== '') {
        try {
            $stmt = $pdo->prepare("INSERT INTO dlp_file_types (extension, category, always_block_regardless_content, description) VALUES (?, ?, ?, ?)");
            $stmt->execute([$extension, $category, $alwaysBlock, $description]);
            $message = 'Da them loai file moi.';
        } catch (PDOException $e) {
            $message = 'Loi: Duoi file nay co the da ton tai.';
        }
    }
}

if (isset($_GET['delete'])) {
    $pdo->prepare("DELETE FROM dlp_file_types WHERE id = ?")->execute([(int)$_GET['delete']]);
    header('Location: file_types.php');
    exit;
}

$fileTypes = $pdo->query("SELECT * FROM dlp_file_types ORDER BY category, extension")->fetchAll();

$pageTitle = 'File Types';
$activeMenu = 'file_types';
require __DIR__ . '/../includes/layout_header.php';
?>

<?php if ($message): ?>
    <div class="success-msg"><?= h($message) ?></div>
<?php endif; ?>

<div class="card">
    <h2>Them loai file moi</h2>
    <form method="POST">
        <input type="hidden" name="action" value="add">
        <div class="form-group">
            <label>Duoi file (khong can dau cham)</label>
            <input type="text" name="extension" placeholder="VD: docx" required>
        </div>
        <div class="form-group">
            <label>Danh muc</label>
            <select name="category">
                <option value="DOCUMENT">DOCUMENT</option>
                <option value="ARCHIVE">ARCHIVE</option>
                <option value="IMAGE">IMAGE</option>
                <option value="EXECUTABLE">EXECUTABLE</option>
                <option value="OTHER">OTHER</option>
            </select>
        </div>
        <div class="form-group">
            <label><input type="checkbox" name="always_block"> Luon chan (khong doc noi dung)</label>
        </div>
        <div class="form-group">
            <label>Mo ta</label>
            <input type="text" name="description">
        </div>
        <button type="submit" class="btn btn-primary">Them</button>
    </form>
</div>

<div class="card">
    <h2>Danh sach File Types (<?= count($fileTypes) ?>)</h2>
    <table>
        <thead><tr><th>Duoi file</th><th>Danh muc</th><th>Luon chan?</th><th>Mo ta</th><th>Hanh dong</th></tr></thead>
        <tbody>
        <?php foreach ($fileTypes as $ft): ?>
            <tr>
                <td>.<?= h($ft['extension']) ?></td>
                <td><?= h($ft['category']) ?></td>
                <td><?= $ft['always_block_regardless_content'] ? 'Co' : 'Khong' ?></td>
                <td><?= h($ft['description']) ?></td>
                <td><a href="file_types.php?delete=<?= (int)$ft['id'] ?>" class="btn btn-danger btn-sm" onclick="return confirm('Xoa loai file nay?')">Xoa</a></td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
</div>

<?php require __DIR__ . '/../includes/layout_footer.php'; ?>