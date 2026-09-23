<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/helpers.php';

$policyId = isset($_GET['id']) ? (int)$_GET['id'] : null;
$isEdit = $policyId !== null;
$message = '';

$groups = $pdo->query("SELECT id, name FROM groups ORDER BY name")->fetchAll();
$devices = $pdo->query("SELECT id, hostname FROM devices ORDER BY hostname")->fetchAll();
$fileTypes = $pdo->query("SELECT * FROM dlp_file_types ORDER BY category, extension")->fetchAll();
$contentRules = $pdo->query("SELECT * FROM content_rules WHERE is_active = 1 ORDER BY category, rule_name")->fetchAll();

$fileTypesByCategory = [];
foreach ($fileTypes as $ft) {
    $fileTypesByCategory[$ft['category']][] = $ft;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = trim($_POST['name'] ?? '');
    $description = trim($_POST['description'] ?? '');
    $targetType = $_POST['target_type'] ?? 'GROUP';
    $targetGroupId = $targetType === 'GROUP' ? (int)($_POST['target_group_id'] ?? 0) : null;
    $targetDeviceIds = $targetType === 'DEVICE' ? ($_POST['target_device_ids'] ?? []) : [];
    $action = $_POST['action_type'] ?? 'REPORT_ONLY';
    $exitPoints = $_POST['exit_points'] ?? [];
    $fileTypeIds = $_POST['file_type_ids'] ?? [];
    $ruleIds = $_POST['rule_ids'] ?? [];

    if ($name === '') {
        $message = 'Vui long nhap ten Policy.';
    } elseif (empty($exitPoints)) {
        $message = 'Vui long tick it nhat 1 Exit Point.';
    } elseif ($targetType === 'GROUP' && !$targetGroupId) {
        $message = 'Vui long chon Group ap dung.';
    } elseif ($targetType === 'DEVICE' && empty($targetDeviceIds)) {
        $message = 'Vui long chon it nhat 1 thiet bi.';
    } else {
        $pdo->beginTransaction();
        try {
            if ($isEdit) {
                $stmt = $pdo->prepare("
                    UPDATE dlp_policies SET name=?, description=?, target_type=?, target_group_id=?, action=?
                    WHERE id=?
                ");
                $stmt->execute([$name, $description, $targetType, $targetGroupId, $action, $policyId]);

                $pdo->prepare("DELETE FROM dlp_policy_devices WHERE policy_id = ?")->execute([$policyId]);
                $pdo->prepare("DELETE FROM dlp_policy_exit_points WHERE policy_id = ?")->execute([$policyId]);
                $pdo->prepare("DELETE FROM dlp_policy_file_types WHERE policy_id = ?")->execute([$policyId]);
                $pdo->prepare("DELETE FROM dlp_policy_content_rules WHERE policy_id = ?")->execute([$policyId]);
            } else {
                $stmt = $pdo->prepare("
                    INSERT INTO dlp_policies (name, description, target_type, target_group_id, action, created_by)
                    VALUES (?, ?, ?, ?, ?, ?)
                ");
                $stmt->execute([$name, $description, $targetType, $targetGroupId, $action, current_admin_name()]);
                $policyId = (int)$pdo->lastInsertId();
            }

            if ($targetType === 'DEVICE') {
                $insert = $pdo->prepare("INSERT INTO dlp_policy_devices (policy_id, device_id) VALUES (?, ?)");
                foreach ($targetDeviceIds as $devId) {
                    $insert->execute([$policyId, (int)$devId]);
                }
            }

            $insert = $pdo->prepare("INSERT INTO dlp_policy_exit_points (policy_id, exit_point_type) VALUES (?, ?)");
            foreach ($exitPoints as $ep) {
                $insert->execute([$policyId, $ep]);
            }

            $insert = $pdo->prepare("INSERT INTO dlp_policy_file_types (policy_id, file_type_id) VALUES (?, ?)");
            foreach ($fileTypeIds as $ftId) {
                $insert->execute([$policyId, (int)$ftId]);
            }

            $insert = $pdo->prepare("INSERT INTO dlp_policy_content_rules (policy_id, content_rule_id) VALUES (?, ?)");
            foreach ($ruleIds as $rId) {
                $insert->execute([$policyId, (int)$rId]);
            }

            $pdo->commit();
            header('Location: policies.php');
            exit;
        } catch (PDOException $e) {
            $pdo->rollBack();
            $message = 'Loi khi luu: ' . $e->getMessage();
        }
    }
}

$policy = [
    'name' => '', 'description' => '', 'target_type' => 'GROUP',
    'target_group_id' => null, 'action' => 'REPORT_ONLY',
];
$selectedExitPoints = [];
$selectedFileTypeIds = [];
$selectedRuleIds = [];
$selectedDeviceIds = [];

if ($isEdit) {
    $stmt = $pdo->prepare("SELECT * FROM dlp_policies WHERE id = ?");
    $stmt->execute([$policyId]);
    $found = $stmt->fetch();
    if (!$found) { die('Khong tim thay Policy.'); }
    $policy = $found;

    $stmt = $pdo->prepare("SELECT exit_point_type FROM dlp_policy_exit_points WHERE policy_id = ?");
    $stmt->execute([$policyId]);
    $selectedExitPoints = array_column($stmt->fetchAll(), 'exit_point_type');

    $stmt = $pdo->prepare("SELECT file_type_id FROM dlp_policy_file_types WHERE policy_id = ?");
    $stmt->execute([$policyId]);
    $selectedFileTypeIds = array_column($stmt->fetchAll(), 'file_type_id');

    $stmt = $pdo->prepare("SELECT content_rule_id FROM dlp_policy_content_rules WHERE policy_id = ?");
    $stmt->execute([$policyId]);
    $selectedRuleIds = array_column($stmt->fetchAll(), 'content_rule_id');

    $stmt = $pdo->prepare("SELECT device_id FROM dlp_policy_devices WHERE policy_id = ?");
    $stmt->execute([$policyId]);
    $selectedDeviceIds = array_column($stmt->fetchAll(), 'device_id');
}

$exitPointLabels = [
    'USB'               => 'USB / Removable Media',
    'CLIPBOARD'         => 'Clipboard',
    'NETWORK_WEB'       => 'Network - Web/Cloud',
    'NETWORK_SCP_SFTP'  => 'Network - SCP/SFTP',
    'NETWORK_FTP'       => 'Network - FTP',
    'RDP'               => 'Remote Desktop (RDP)',
];

$pageTitle = $isEdit ? 'Sua Policy' : 'Tao Policy moi';
$activeMenu = 'policies';
require __DIR__ . '/../includes/layout_header.php';
?>

<?php if ($message): ?>
    <div class="error-msg"><?= h($message) ?></div>
<?php endif; ?>

<form method="POST">
    <div class="card">
        <h2>Thong tin chung</h2>
        <div class="form-group">
            <label>Ten Policy</label>
            <input type="text" name="name" required value="<?= h($policy['name']) ?>"
                   placeholder="VD: Chan CCCD ra USB - Kinh doanh">
        </div>
        <div class="form-group">
            <label>Mo ta</label>
            <input type="text" name="description" value="<?= h($policy['description']) ?>">
        </div>
        <div class="form-group">
            <label>Hanh dong</label>
            <select name="action_type">
                <option value="BLOCK" <?= $policy['action'] === 'BLOCK' ? 'selected' : '' ?>>BLOCK — Chan hanh vi</option>
                <option value="REPORT_ONLY" <?= $policy['action'] === 'REPORT_ONLY' ? 'selected' : '' ?>>REPORT_ONLY — Chi ghi log</option>
            </select>
        </div>
    </div>

    <div class="card">
        <h2>Doi tuong ap dung</h2>
        <div class="form-group">
            <label><input type="radio" name="target_type" value="GROUP"
                    <?= $policy['target_type'] === 'GROUP' ? 'checked' : '' ?> onchange="toggleTarget()"> Theo Group</label>
            <label style="margin-left:20px;"><input type="radio" name="target_type" value="DEVICE"
                    <?= $policy['target_type'] === 'DEVICE' ? 'checked' : '' ?> onchange="toggleTarget()"> Theo thiet bi cu the</label>
        </div>
        <div id="target-group-box" class="form-group" style="<?= $policy['target_type'] !== 'GROUP' ? 'display:none' : '' ?>">
            <label>Chon Group</label>
            <select name="target_group_id">
                <option value="">-- Chon Group --</option>
                <?php foreach ($groups as $g): ?>
                    <option value="<?= (int)$g['id'] ?>" <?= $policy['target_group_id'] == $g['id'] ? 'selected' : '' ?>>
                        <?= h($g['name']) ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </div>
        <div id="target-device-box" class="form-group" style="<?= $policy['target_type'] !== 'DEVICE' ? 'display:none' : '' ?>">
            <label>Chon thiet bi (co the chon nhieu)</label>
            <?php foreach ($devices as $d): ?>
                <div>
                    <label>
                        <input type="checkbox" name="target_device_ids[]" value="<?= (int)$d['id'] ?>"
                            <?= in_array($d['id'], $selectedDeviceIds) ? 'checked' : '' ?>>
                        <?= h($d['hostname']) ?>
                    </label>
                </div>
            <?php endforeach; ?>
        </div>
    </div>

    <div class="card">
        <h2>Buoc 1 — Tick Exit Point</h2>
        <?php foreach ($exitPointLabels as $key => $label): ?>
            <label style="display:inline-block; width:280px; margin-bottom:8px;">
                <input type="checkbox" name="exit_points[]" value="<?= $key ?>"
                    <?= in_array($key, $selectedExitPoints) ? 'checked' : '' ?>>
                <?= h($label) ?>
            </label>
        <?php endforeach; ?>
    </div>

    <div class="card">
        <h2>Buoc 2 — Tick File Type can Block</h2>
        <p style="font-size:13px; color:#616e7c; margin-bottom:10px;">
            Nhom ARCHIVE (zip/rar/7z) se luon bi chan ngay, khong doc noi dung ben trong.
        </p>
        <?php foreach ($fileTypesByCategory as $category => $items): ?>
            <p style="font-weight:600; margin-top:10px;"><?= h($category) ?></p>
            <?php foreach ($items as $ft): ?>
                <label style="display:inline-block; width:160px; margin-bottom:6px;">
                    <input type="checkbox" name="file_type_ids[]" value="<?= (int)$ft['id'] ?>"
                        <?= in_array($ft['id'], $selectedFileTypeIds) ? 'checked' : '' ?>>
                    .<?= h($ft['extension']) ?>
                    <?= $ft['always_block_regardless_content'] ? ' <span style="color:#b3221d;font-size:11px;">(luon chan)</span>' : '' ?>
                </label>
            <?php endforeach; ?>
        <?php endforeach; ?>
    </div>

    <div class="card">
        <h2>Buoc 3 — Gan PII / Content Rules</h2>
        <p style="font-size:13px; color:#616e7c; margin-bottom:10px;">
            Chi ap dung cho file KHONG thuoc nhom "luon chan" o Buoc 2. Chua co rule?
            Tao truoc o trang <a href="content_rules.php" target="_blank">PII / Content Rules</a>.
        </p>
        <table>
            <thead><tr><th></th><th>Ten rule</th><th>Loai</th><th>Danh muc</th><th>Muc do</th></tr></thead>
            <tbody>
            <?php foreach ($contentRules as $r): ?>
                <tr>
                    <td><input type="checkbox" name="rule_ids[]" value="<?= (int)$r['id'] ?>"
                        <?= in_array($r['id'], $selectedRuleIds) ? 'checked' : '' ?>></td>
                    <td><?= h($r['rule_name']) ?></td>
                    <td><?= h($r['rule_type']) ?></td>
                    <td><?= h($r['category']) ?></td>
                    <td><span class="badge <?= severity_badge_class($r['severity']) ?>"><?= h($r['severity']) ?></span></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <div class="card">
        <button type="submit" class="btn btn-primary"><?= $isEdit ? 'Cap nhat Policy' : 'Tao Policy' ?></button>
        <a href="policies.php" class="btn btn-secondary">Huy</a>
    </div>
</form>

<script>
function toggleTarget() {
    const isGroup = document.querySelector('input[name="target_type"][value="GROUP"]').checked;
    document.getElementById('target-group-box').style.display = isGroup ? '' : 'none';
    document.getElementById('target-device-box').style.display = isGroup ? 'none' : '';
}
</script>

<?php require __DIR__ . '/../includes/layout_footer.php'; ?>