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


// Destination used only by the Server-side Wazuh TCP syslog forwarder.
// Run sql/migrations/add_wazuh_settings.sql on existing installations first.
$wazuhError = '';
$wazuhSaved = false;
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'save_wazuh') {
    $ip = trim((string)($_POST['wazuh_ip'] ?? ''));
    $portRaw = trim((string)($_POST['wazuh_port'] ?? ''));
    $validIp = filter_var($ip, FILTER_VALIDATE_IP) !== false;
    $validPort = ctype_digit($portRaw) && (int)$portRaw >= 1 && (int)$portRaw <= 65535;
    if (!$validIp || !$validPort) {
        $wazuhError = 'IP SIEM hoac port khong hop le (port 1-65535).';
    } else {
        $stmt = $pdo->prepare("
            INSERT INTO wazuh_settings (id, siem_ip, siem_port)
            VALUES (1, ?, ?)
            ON DUPLICATE KEY UPDATE siem_ip = VALUES(siem_ip), siem_port = VALUES(siem_port)
        ");
        $stmt->execute([$ip, (int)$portRaw]);
        $wazuhSaved = true;
        $message = 'Da luu IP/port Wazuh. DLP Server se gui TCP Syslog khi nhan log moi.';
    }
}

$wazuh = $pdo->query("SELECT siem_ip, siem_port, updated_at FROM wazuh_settings WHERE id = 1")->fetch();
if (!$wazuh) {
    $wazuh = ['siem_ip' => '', 'siem_port' => '514', 'updated_at' => null];
}
if ($wazuhError !== '') {
    $wazuh['siem_ip'] = trim((string)($_POST['wazuh_ip'] ?? ''));
    $wazuh['siem_port'] = trim((string)($_POST['wazuh_port'] ?? ''));
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
    <h2>Wazuh SIEM Integration</h2>
    <p style="font-size:13px; color:#616e7c; margin-bottom:14px;">
        DLP Server tu dong gui TCP Syslog sau khi luu log tu Agent vao MySQL.
        Neu SIEM mat ket noi, log duoc giu trong hang doi va thu lai bang CLI worker.
        <strong>Can cau hinh Syslog TCP receiver tren Wazuh va chay worker dinh ky.</strong>
        Port phai khop voi dich vu nhan log duoc cau hinh tren Wazuh.
    </p>
    <?php if ($wazuhError): ?>
        <div class="error-msg" role="alert" style="margin-bottom:14px; color:#b42318;"><?= h($wazuhError) ?></div>
    <?php endif; ?>
    <form method="POST">
        <input type="hidden" name="action" value="save_wazuh">
        <div class="form-group">
            <label for="wazuh-ip">SIEM Server IP</label>
            <input id="wazuh-ip" type="text" name="wazuh_ip" maxlength="45"
                   placeholder="VD: 192.168.106.131"
                   value="<?= h((string)$wazuh['siem_ip']) ?>" required>
        </div>
        <div class="form-group">
            <label for="wazuh-port">SIEM Port</label>
            <input id="wazuh-port" type="number" name="wazuh_port" min="1" max="65535"
                   value="<?= h((string)$wazuh['siem_port']) ?>" required>
        </div>
        <button type="submit" class="btn btn-primary">Luu cau hinh Wazuh</button>
        <?php if ($wazuh['updated_at']): ?>
            <p style="font-size:12px; color:#616e7c; margin-top:10px;">
                Cap nhat lan cuoi: <?= h(format_datetime($wazuh['updated_at'])) ?>
            </p>
        <?php endif; ?>
    </form>
</div>

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