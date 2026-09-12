<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/helpers.php';

// Cap nhat trang thai OFFLINE neu qua 5 phut khong heartbeat
$pdo->exec("UPDATE endpoints SET status = 'OFFLINE' WHERE last_seen < (NOW() - INTERVAL 5 MINUTE)");

$message = '';
$newToken = '';

// --- Them endpoint moi (server tu sinh API token) ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'add') {
    $hostname = trim($_POST['hostname'] ?? '');
    $username = trim($_POST['username'] ?? '');
    $groupId = (int)($_POST['group_id'] ?? 0);

    if ($hostname !== '' && $groupId > 0) {
        $token = generate_api_token();
        try {
            $stmt = $pdo->prepare("INSERT INTO endpoints (hostname, username, group_id, api_token) VALUES (?, ?, ?, ?)");
            $stmt->execute([$hostname, $username, $groupId, $token]);
            $message = 'Da tao endpoint moi. HAY LUU LAI TOKEN BEN DUOI - se khong hien thi lai day du sau khi roi trang nay.';
            $newToken = $token;
        } catch (PDOException $e) {
            $message = 'Loi: Hostname nay co the da ton tai.';
        }
    } else {
        $message = 'Vui long nhap hostname va chon nhom.';
    }
}

if (isset($_GET['delete'])) {
    $pdo->prepare("DELETE FROM endpoints WHERE id = ?")->execute([(int)$_GET['delete']]);
    header('Location: endpoints.php');
    exit;
}

$groups = $pdo->query("SELECT id, name FROM groups ORDER BY name")->fetchAll();

$endpoints = $pdo->query("
    SELECT e.*, g.name as group_name
    FROM endpoints e
    LEFT JOIN groups g ON e.group_id = g.id
    ORDER BY e.created_at DESC
")->fetchAll();

$pageTitle = 'Endpoints';
$activeMenu = 'endpoints';
require __DIR__ . '/../includes/layout_header.php';
?>

<?php if ($message): ?>
    <div class="<?= $newToken ? 'success-msg' : 'error-msg' ?>">
        <?= h($message) ?>
        <?php if ($newToken): ?>
            <div style="margin-top:8px; font-family:monospace; background:#fff; padding:8px; border-radius:4px; word-break:break-all;">
                <?= h($newToken) ?>
            </div>
        <?php endif; ?>
    </div>
<?php endif; ?>

<div class="card">
    <h2>Them Endpoint moi</h2>
    <p style="font-size:13px; color:#616e7c; margin-bottom:14px;">
        Sau khi tao, copy API Token hien thi va dien vao file config cua Agent tren may do (xem docs/API_CONTRACT.md).
    </p>
    <form method="POST">
        <input type="hidden" name="action" value="add">
        <div class="form-group">
            <label>Hostname (ten may)</label>
            <input type="text" name="hostname" placeholder="VD: PC-KINHDOANH-02" required>
        </div>
        <div class="form-group">
            <label>Username (nguoi dung chinh cua may, tuy chon)</label>
            <input type="text" name="username" placeholder="VD: nguyenvanc">
        </div>
        <div class="form-group">
            <label>Nhom</label>
            <select name="group_id" required>
                <option value="">-- Chon nhom --</option>
                <?php foreach ($groups as $g): ?>
                    <option value="<?= (int)$g['id'] ?>"><?= h($g['name']) ?></option>
                <?php endforeach; ?>
            </select>
        </div>
        <button type="submit" class="btn btn-primary">Tao Endpoint + Sinh Token</button>
    </form>
</div>

<div class="card">
    <h2>Danh sach Endpoint (<?= count($endpoints) ?>)</h2>
    <table>
        <thead>
        <tr><th>Trang thai</th><th>Hostname</th><th>User</th><th>Nhom</th><th>Version</th><th>Lan cuoi hoat dong</th><th>Hanh dong</th></tr>
        </thead>
        <tbody>
        <?php if (empty($endpoints)): ?>
            <tr><td colspan="7">Chua co endpoint nao.</td></tr>
        <?php endif; ?>
        <?php foreach ($endpoints as $e): ?>
            <tr>
                <td>
                    <span class="dot <?= $e['status'] === 'ONLINE' ? 'dot-online' : 'dot-offline' ?>"></span>
                    <?= h($e['status']) ?>
                </td>
                <td><?= h($e['hostname']) ?></td>
                <td><?= h($e['username'] ?? '-') ?></td>
                <td><?= h($e['group_name'] ?? '-') ?></td>
                <td><?= h($e['agent_version'] ?? '-') ?></td>
                <td><?= h(format_datetime($e['last_seen'])) ?></td>
                <td>
                    <a href="endpoints.php?delete=<?= (int)$e['id'] ?>" class="btn btn-danger btn-sm"
                       onclick="return confirm('Xoa endpoint nay? Agent tren may do se khong con goi API duoc.')">Xoa</a>
                </td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
</div>

<?php require __DIR__ . '/../includes/layout_footer.php'; ?>
