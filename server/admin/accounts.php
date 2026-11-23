<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/helpers.php';
require_super_admin();

$modules = [
    'dashboard' => 'Dashboard', 'devices' => 'Devices', 'groups' => 'Groups',
    'policies' => 'DLP Policies', 'content_rules' => 'PII / Content Rules',
    'file_types' => 'File Types', 'usb_whitelist' => 'USB Whitelist',
    'network_blacklist' => 'Network Blacklist', 'logs' => 'Logs', 'settings' => 'Settings'
];
$message = $error = '';
$csrf = $_SESSION['csrf_accounts'] ??= bin2hex(random_bytes(32));

function save_account_permissions(PDO $pdo, int $userId, array $modules): void {
    $pdo->prepare("DELETE FROM admin_permissions WHERE admin_id = ?")->execute([$userId]);
    $stmt = $pdo->prepare("INSERT INTO admin_permissions (admin_id, module_key, can_view, can_edit) VALUES (?, ?, ?, ?)");
    foreach ($modules as $key => $_label) {
        $level = $_POST['permissions'][$key] ?? 'none';
        if (!in_array($level, ['none', 'view', 'edit'], true)) $level = 'none';
        if ($level !== 'none') $stmt->execute([$userId, $key, 1, $level === 'edit' ? 1 : 0]);
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($csrf, (string)($_POST['csrf'] ?? ''))) {
        $error = 'Phien lam viec khong hop le. Hay tai lai trang.';
    } else {
        $action = $_POST['action'] ?? '';
        try {
            if ($action === 'create') {
                $username = trim((string)($_POST['username'] ?? ''));
                $fullName = trim((string)($_POST['full_name'] ?? ''));
                $password = (string)($_POST['password'] ?? '');
                if (!preg_match('/^[A-Za-z0-9_.-]{3,100}$/', $username)) throw new RuntimeException('Username phai co 3-100 ky tu: chu, so, _, ., -.');
                if (strlen($password) < 10) throw new RuntimeException('Mat khau phai co it nhat 10 ky tu.');
                $stmt = $pdo->prepare("INSERT INTO admins (username, password_hash, full_name, role, is_active) VALUES (?, ?, ?, 'VIEWER', 1)");
                $stmt->execute([$username, password_hash($password, PASSWORD_DEFAULT), $fullName]);
                $message = 'Da tao tai khoan. Hay cap quyen trong danh sach ben duoi.';
            } elseif ($action === 'permissions') {
                $userId = (int)($_POST['user_id'] ?? 0);
                if ($userId === (int)$_SESSION['admin_id']) throw new RuntimeException('Khong the thay doi quyen cua chinh tai khoan dang dang nhap.');
                $stmt = $pdo->prepare("SELECT role FROM admins WHERE id = ?");
                $stmt->execute([$userId]); $target = $stmt->fetch();
                if (!$target || $target['role'] === 'SUPER_ADMIN') throw new RuntimeException('Khong the sua quyen cua Super Admin.');
                save_account_permissions($pdo, $userId, $modules);
                $message = 'Da cap nhat phan quyen.';
            } elseif ($action === 'password') {
                $userId = (int)($_POST['user_id'] ?? 0); $password = (string)($_POST['password'] ?? '');
                if (strlen($password) < 10) throw new RuntimeException('Mat khau moi phai co it nhat 10 ky tu.');
                $stmt = $pdo->prepare("UPDATE admins SET password_hash = ? WHERE id = ? AND role <> 'SUPER_ADMIN'");
                $stmt->execute([password_hash($password, PASSWORD_DEFAULT), $userId]);
                $message = 'Da dat lai mat khau.';
            } elseif ($action === 'status') {
                $userId = (int)($_POST['user_id'] ?? 0);
                if ($userId === (int)$_SESSION['admin_id']) throw new RuntimeException('Khong the tu vo hieu hoa tai khoan dang dang nhap.');
                $pdo->prepare("UPDATE admins SET is_active = NOT is_active WHERE id = ? AND role <> 'SUPER_ADMIN'")->execute([$userId]);
                $message = 'Da cap nhat trang thai tai khoan.';
            } elseif ($action === 'delete') {
                $userId = (int)($_POST['user_id'] ?? 0);
                if ($userId === (int)$_SESSION['admin_id']) throw new RuntimeException('Khong the xoa tai khoan dang dang nhap.');
                $pdo->prepare("DELETE FROM admins WHERE id = ? AND role <> 'SUPER_ADMIN'")->execute([$userId]);
                $message = 'Da xoa tai khoan.';
            }
        } catch (PDOException $e) {
            $error = $e->getCode() === '23000' ? 'Username da ton tai.' : 'Khong the thuc hien thao tac database.';
        } catch (RuntimeException $e) { $error = $e->getMessage(); }
    }
}

$users = $pdo->query("SELECT id, username, full_name, role, is_active, created_at, last_login FROM admins ORDER BY role = 'SUPER_ADMIN' DESC, username")->fetchAll();
$rows = $pdo->query("SELECT admin_id, module_key, can_view, can_edit FROM admin_permissions")->fetchAll();
$permissionMap = [];
foreach ($rows as $row) $permissionMap[(int)$row['admin_id']][$row['module_key']] = $row['can_edit'] ? 'edit' : ($row['can_view'] ? 'view' : 'none');

$pageTitle = 'Quan ly tai khoan';
$activeMenu = 'accounts';
require __DIR__ . '/../includes/layout_header.php';
?>
<?php if ($message): ?><div class="success-msg"><?= h($message) ?></div><?php endif; ?>
<?php if ($error): ?><div class="error-msg"><?= h($error) ?></div><?php endif; ?>

<div class="card">
    <h2>Tao tai khoan moi</h2>
    <p>User moi la tai khoan thuong, khong co quyen mac dinh. Super Admin se cap quyen sau khi tao.</p>
    <form method="POST">
        <input type="hidden" name="csrf" value="<?= h($csrf) ?>"><input type="hidden" name="action" value="create">
        <div class="form-group"><label>Username</label><input name="username" required minlength="3" maxlength="100" pattern="[A-Za-z0-9_.-]+"></div>
        <div class="form-group"><label>Ho ten</label><input name="full_name" maxlength="100"></div>
        <div class="form-group"><label>Mat khau ban dau (toi thieu 10 ky tu)</label><input type="password" name="password" required minlength="10" autocomplete="new-password"></div>
        <button class="btn btn-primary" type="submit">Tao tai khoan</button>
    </form>
</div>

<div class="card">
    <h2>Danh sach tai khoan (<?= count($users) ?>)</h2>
    <?php foreach ($users as $user): $uid = (int)$user['id']; ?>
    <div style="border:1px solid #e5e7eb;border-radius:8px;padding:16px;margin:12px 0;">
        <div style="display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;">
            <div><strong><?= h($user['username']) ?></strong> — <?= h($user['full_name'] ?? '') ?>
                <div style="font-size:12px;color:#667085;margin-top:4px;"><?= h($user['role']) ?> · <?= $user['is_active'] ? 'Dang hoat dong' : 'Da vo hieu hoa' ?> · Dang nhap cuoi: <?= h($user['last_login'] ?? 'Chua dang nhap') ?></div>
            </div>
            <?php if ($user['role'] !== 'SUPER_ADMIN'): ?>
            <form method="POST"><input type="hidden" name="csrf" value="<?= h($csrf) ?>"><input type="hidden" name="action" value="status"><input type="hidden" name="user_id" value="<?= $uid ?>"><button class="btn btn-secondary btn-sm" type="submit"><?= $user['is_active'] ? 'Vo hieu hoa' : 'Kich hoat' ?></button></form>
            <?php endif; ?>
        </div>
        <?php if ($user['role'] !== 'SUPER_ADMIN'): ?>
        <form method="POST" style="margin-top:14px;">
            <input type="hidden" name="csrf" value="<?= h($csrf) ?>"><input type="hidden" name="action" value="permissions"><input type="hidden" name="user_id" value="<?= $uid ?>">
            <strong>Phan quyen theo chuc nang</strong>
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;margin:10px 0;">
                <?php foreach ($modules as $key => $label): $level = $permissionMap[$uid][$key] ?? 'none'; ?>
                <label style="display:flex;justify-content:space-between;align-items:center;gap:8px;"><span><?= h($label) ?></span><select name="permissions[<?= h($key) ?>]"><option value="none" <?= $level==='none'?'selected':'' ?>>No access</option><option value="view" <?= $level==='view'?'selected':'' ?>>View</option><option value="edit" <?= $level==='edit'?'selected':'' ?>>Edit</option></select></label>
                <?php endforeach; ?>
            </div>
            <button class="btn btn-primary btn-sm" type="submit">Luu quyen</button>
        </form>
        <form method="POST" style="display:flex;gap:8px;align-items:end;margin-top:12px;flex-wrap:wrap;">
            <input type="hidden" name="csrf" value="<?= h($csrf) ?>"><input type="hidden" name="action" value="password"><input type="hidden" name="user_id" value="<?= $uid ?>">
            <div class="form-group" style="margin:0;min-width:240px;"><label>Dat lai mat khau</label><input type="password" name="password" minlength="10" required autocomplete="new-password"></div><button class="btn btn-secondary btn-sm" type="submit">Cap nhat mat khau</button>
        </form>
        <form method="POST" style="margin-top:10px;" onsubmit="return confirm('Xoa tai khoan nay?');"><input type="hidden" name="csrf" value="<?= h($csrf) ?>"><input type="hidden" name="action" value="delete"><input type="hidden" name="user_id" value="<?= $uid ?>"><button class="btn btn-danger btn-sm" type="submit">Xoa tai khoan</button></form>
        <?php endif; ?>
    </div>
    <?php endforeach; ?>
</div>
<?php require __DIR__ . '/../includes/layout_footer.php'; ?>
