<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/helpers.php';

$policyId = isset($_GET['id']) ? (int)$_GET['id'] : null;
$error = '';

$exitPointLabels = [
    'USB'               => 'USB / Removable Media',
    'CLIPBOARD'         => 'Clipboard',
    'NETWORK_WEB'       => 'Network - Web/Cloud',
    'NETWORK_SCP_SFTP'  => 'Network - SCP/SFTP',
    'NETWORK_FTP'       => 'Network - FTP',
    'RDP'               => 'Remote Desktop (RDP)',
    'EMAIL_CLIENT'      => 'E-mail Client (SMTP)',
    'CLOUD_SYNC_FOLDER' => 'Cloud Sync Folder (Dropbox/OneDrive/Google Drive)',
];

$groups = $pdo->query("SELECT id, name FROM groups ORDER BY name")->fetchAll();
$devices = $pdo->query("SELECT id, hostname, ip_address FROM devices ORDER BY hostname")->fetchAll();
$fileTypes = $pdo->query("SELECT id, extension, category, always_block_regardless_content FROM dlp_file_types ORDER BY category, extension")->fetchAll();
$contentRules = $pdo->query("SELECT id, rule_name, category, severity FROM content_rules WHERE is_active = 1 ORDER BY category, rule_name")->fetchAll();

// Gom file types theo category de hien thi
$fileTypesByCategory = [];
foreach ($fileTypes as $ft) {
    $fileTypesByCategory[$ft['category']][] = $ft;
}

// Du lieu mac dinh (tao moi)
$policy = [
    'name' => '', 'description' => '', 'target_type' => 'GROUP',
    'target_group_id' => null, 'action' => 'REPORT_ONLY', 'is_active' => 1,
];
$selectedExitPoints = [];
$selectedFileTypes = [];
$selectedContentRules = [];
$selectedDevices = [];
$allowedLocationsText = '';
$allowedFilesText = '';

// Load du lieu khi edit
if ($policyId) {
    $stmt = $pdo->prepare("SELECT * FROM dlp_policies WHERE id = ?");
    $stmt->execute([$policyId]);
    $found = $stmt->fetch();
    if (!$found) {
        die('Policy không tồn tại.');
    }
    $policy = $found;

    $stmt = $pdo->prepare("SELECT exit_point_type FROM dlp_policy_exit_points WHERE policy_id = ?");
    $stmt->execute([$policyId]);
    $selectedExitPoints = array_column($stmt->fetchAll(), 'exit_point_type');

    $stmt = $pdo->prepare("SELECT file_type_id FROM dlp_policy_file_types WHERE policy_id = ?");
    $stmt->execute([$policyId]);
    $selectedFileTypes = array_column($stmt->fetchAll(), 'file_type_id');

    $stmt = $pdo->prepare("SELECT content_rule_id FROM dlp_policy_content_rules WHERE policy_id = ?");
    $stmt->execute([$policyId]);
    $selectedContentRules = array_column($stmt->fetchAll(), 'content_rule_id');

    $stmt = $pdo->prepare("SELECT device_id FROM dlp_policy_devices WHERE policy_id = ?");
    $stmt->execute([$policyId]);
    $selectedDevices = array_column($stmt->fetchAll(), 'device_id');

    $stmt = $pdo->prepare("SELECT exception_type, value FROM dlp_policy_exceptions WHERE policy_id = ?");
    $stmt->execute([$policyId]);
    $locs = []; $files = [];
    foreach ($stmt->fetchAll() as $ex) {
        if ($ex['exception_type'] === 'ALLOWED_LOCATION') $locs[] = $ex['value'];
        else $files[] = $ex['value'];
    }
    $allowedLocationsText = implode("\n", $locs);
    $allowedFilesText = implode("\n", $files);
}

// Xu ly submit
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = trim($_POST['name'] ?? '');
    $description = trim($_POST['description'] ?? '');
    $targetType = $_POST['target_type'] ?? 'GROUP';
    $targetGroupId = $targetType === 'GROUP' ? (int)($_POST['target_group_id'] ?? 0) : null;
    $action = $_POST['action'] ?? 'REPORT_ONLY';
    $isActive = isset($_POST['is_active']) ? 1 : 0;
    $exitPoints = $_POST['exit_points'] ?? [];
    $fileTypeIds = $_POST['file_types'] ?? [];
    $contentRuleIds = $_POST['content_rules'] ?? [];
    $targetDeviceIds = $_POST['target_devices'] ?? [];
    $allowedLocations = array_filter(array_map('trim', explode("\n", $_POST['allowed_locations'] ?? '')));
    $allowedFiles = array_filter(array_map('trim', explode("\n", $_POST['allowed_files'] ?? '')));

    if ($name === '') {
        $error = 'Vui lòng nhập tên policy.';
    } elseif ($targetType === 'GROUP' && !$targetGroupId) {
        $error = 'Vui lòng chọn Group mục tiêu.';
    } elseif ($targetType === 'DEVICE' && empty($targetDeviceIds)) {
        $error = 'Vui lòng chọn ít nhất 1 thiết bị mục tiêu.';
    } elseif (empty($exitPoints)) {
        $error = 'Vui lòng chọn ít nhất 1 Exit Point.';
    } else {
        $pdo->beginTransaction();
        try {
            if ($policyId) {
                $stmt = $pdo->prepare("
                    UPDATE dlp_policies
                    SET name=?, description=?, target_type=?, target_group_id=?, action=?, is_active=?
                    WHERE id=?
                ");
                $stmt->execute([$name, $description, $targetType, $targetGroupId, $action, $isActive, $policyId]);
            } else {
                $stmt = $pdo->prepare("
                    INSERT INTO dlp_policies (name, description, target_type, target_group_id, action, is_active, created_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ");
                $stmt->execute([$name, $description, $targetType, $targetGroupId, $action, $isActive, current_admin_name()]);
                $policyId = $pdo->lastInsertId();
            }

            // Xoa het junction cu, insert lai (don gian, de bao tri)
            $pdo->prepare("DELETE FROM dlp_policy_devices WHERE policy_id = ?")->execute([$policyId]);
            $pdo->prepare("DELETE FROM dlp_policy_exit_points WHERE policy_id = ?")->execute([$policyId]);
            $pdo->prepare("DELETE FROM dlp_policy_file_types WHERE policy_id = ?")->execute([$policyId]);
            $pdo->prepare("DELETE FROM dlp_policy_content_rules WHERE policy_id = ?")->execute([$policyId]);
            $pdo->prepare("DELETE FROM dlp_policy_exceptions WHERE policy_id = ?")->execute([$policyId]);

            if ($targetType === 'DEVICE') {
                $ins = $pdo->prepare("INSERT INTO dlp_policy_devices (policy_id, device_id) VALUES (?, ?)");
                foreach ($targetDeviceIds as $did) $ins->execute([$policyId, (int)$did]);
            }

            $ins = $pdo->prepare("INSERT INTO dlp_policy_exit_points (policy_id, exit_point_type) VALUES (?, ?)");
            foreach ($exitPoints as $ep) $ins->execute([$policyId, $ep]);

            $ins = $pdo->prepare("INSERT INTO dlp_policy_file_types (policy_id, file_type_id) VALUES (?, ?)");
            foreach ($fileTypeIds as $ftid) $ins->execute([$policyId, (int)$ftid]);

            $ins = $pdo->prepare("INSERT INTO dlp_policy_content_rules (policy_id, content_rule_id) VALUES (?, ?)");
            foreach ($contentRuleIds as $crid) $ins->execute([$policyId, (int)$crid]);

            $ins = $pdo->prepare("INSERT INTO dlp_policy_exceptions (policy_id, exception_type, value) VALUES (?, ?, ?)");
            foreach ($allowedLocations as $loc) $ins->execute([$policyId, 'ALLOWED_LOCATION', $loc]);
            foreach ($allowedFiles as $f) $ins->execute([$policyId, 'ALLOWED_FILE', $f]);

            $pdo->commit();
            header('Location: policies.php');
            exit;
        } catch (Exception $e) {
            $pdo->rollBack();
            $error = 'Lỗi khi lưu policy: ' . $e->getMessage();
        }
    }

    // Giu lai gia tri da nhap neu co loi, de khong mat form
    $policy = array_merge($policy, [
        'name' => $name, 'description' => $description, 'target_type' => $targetType,
        'target_group_id' => $targetGroupId, 'action' => $action, 'is_active' => $isActive,
    ]);
    $selectedExitPoints = $exitPoints;
    $selectedFileTypes = $fileTypeIds;
    $selectedContentRules = $contentRuleIds;
    $selectedDevices = $targetDeviceIds;
    $allowedLocationsText = implode("\n", $allowedLocations);
    $allowedFilesText = implode("\n", $allowedFiles);
}

$pageTitle = $policyId ? 'Sửa Policy' : 'Tạo Policy mới';
require_once __DIR__ . '/../includes/layout_header.php';
?>

<div class="page-header">
    <h1><?= h($pageTitle) ?></h1>
</div>

<?php if ($error): ?><div class="alert alert-error"><?= h($error) ?></div><?php endif; ?>

<form method="POST">

    <div class="form-section">
        <h3>Thông tin chung</h3>
        <div class="form-group">
            <label>Tên Policy</label>
            <input type="text" name="name" value="<?= h($policy['name']) ?>" required>
        </div>
        <div class="form-group">
            <label>Mô tả</label>
            <textarea name="description" rows="2"><?= h($policy['description']) ?></textarea>
        </div>
        <div class="form-group">
            <label>Action</label>
            <select name="action">
                <option value="BLOCK" <?= $policy['action'] === 'BLOCK' ? 'selected' : '' ?>>BLOCK (chặn thật)</option>
                <option value="REPORT_ONLY" <?= $policy['action'] === 'REPORT_ONLY' ? 'selected' : '' ?>>REPORT_ONLY (chỉ ghi log)</option>
            </select>
        </div>
        <div class="form-group">
            <label><input type="checkbox" name="is_active" <?= $policy['is_active'] ? 'checked' : '' ?>> Kích hoạt policy</label>
        </div>
    </div>

    <div class="form-section">
        <h3>Mục tiêu áp dụng</h3>
        <label><input type="radio" name="target_type" value="GROUP" onclick="toggleTarget()"
            <?= $policy['target_type'] === 'GROUP' ? 'checked' : '' ?>> Theo Group</label>
        <label style="margin-left:20px;"><input type="radio" name="target_type" value="DEVICE" onclick="toggleTarget()"
            <?= $policy['target_type'] === 'DEVICE' ? 'checked' : '' ?>> Theo Thiết bị cụ thể</label>

        <div id="targetGroupBox" style="margin-top:10px; <?= $policy['target_type'] !== 'GROUP' ? 'display:none;' : '' ?>">
            <select name="target_group_id">
                <option value="">-- Chọn Group --</option>
                <?php foreach ($groups as $g): ?>
                <option value="<?= $g['id'] ?>" <?= $policy['target_group_id'] == $g['id'] ? 'selected' : '' ?>>
                    <?= h($g['name']) ?>
                </option>
                <?php endforeach; ?>
            </select>
        </div>

        <div id="targetDeviceBox" style="margin-top:10px; <?= $policy['target_type'] !== 'DEVICE' ? 'display:none;' : '' ?>">
            <div class="checkbox-list">
                <?php foreach ($devices as $d): ?>
                <label>
                    <input type="checkbox" name="target_devices[]" value="<?= $d['id'] ?>"
                        <?= in_array($d['id'], $selectedDevices) ? 'checked' : '' ?>>
                    <?= h($d['hostname']) ?> (<?= h($d['ip_address']) ?>)
                </label><br>
                <?php endforeach; ?>
            </div>
        </div>
    </div>

    <div class="form-section">
        <h3>Bước 1 — Tick Exit Point cần kiểm soát</h3>
        <div class="checkbox-list">
            <?php foreach ($exitPointLabels as $value => $label): ?>
            <label>
                <input type="checkbox" name="exit_points[]" value="<?= $value ?>"
                    <?= in_array($value, $selectedExitPoints) ? 'checked' : '' ?>>
                <?= h($label) ?>
            </label><br>
            <?php endforeach; ?>
        </div>
    </div>

    <div class="form-section">
        <h3>Bước 2 — Tick File Type cần chặn</h3>
        <?php foreach ($fileTypesByCategory as $category => $items): ?>
        <h4><?= h($category) ?></h4>
        <div class="checkbox-list">
            <?php foreach ($items as $ft): ?>
            <label>
                <input type="checkbox" name="file_types[]" value="<?= $ft['id'] ?>"
                    <?= in_array($ft['id'], $selectedFileTypes) ? 'checked' : '' ?>>
                .<?= h($ft['extension']) ?>
                <?= $ft['always_block_regardless_content'] ? '<small style="color:#c00;">(luôn chặn)</small>' : '' ?>
            </label><br>
            <?php endforeach; ?>
        </div>
        <?php endforeach; ?>
    </div>

    <div class="form-section">
        <h3>Bước 3 — Gán PII / Content Rules</h3>
        <table class="data-table">
            <thead><tr><th></th><th>Tên Rule</th><th>Category</th><th>Severity</th></tr></thead>
            <tbody>
            <?php foreach ($contentRules as $cr): ?>
            <tr>
                <td><input type="checkbox" name="content_rules[]" value="<?= $cr['id'] ?>"
                    <?= in_array($cr['id'], $selectedContentRules) ? 'checked' : '' ?>></td>
                <td><?= h($cr['rule_name']) ?></td>
                <td><?= h($cr['category']) ?></td>
                <td><span class="badge <?= severity_badge_class($cr['severity']) ?>"><?= h($cr['severity']) ?></span></td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <div class="form-section">
        <h3>Bước 4 — Ngoại lệ (Allowed Files / Allowed Locations)</h3>
        <p class="hint">File hoặc đường dẫn nằm trong danh sách này sẽ được bỏ qua, không bị chặn dù policy đang BLOCK.</p>
        <div class="form-group">
            <label>Allowed Locations (mỗi dòng 1 đường dẫn hoặc domain/IP)</label>
            <textarea name="allowed_locations" rows="3" placeholder="C:\Shared\Export\&#10;drive.company.com"><?= h($allowedLocationsText) ?></textarea>
        </div>
        <div class="form-group">
            <label>Allowed Files (mỗi dòng 1 tên file hoặc đường dẫn file)</label>
            <textarea name="allowed_files" rows="3" placeholder="mau_hopdong.docx&#10;C:\Templates\baocao_mau.xlsx"><?= h($allowedFilesText) ?></textarea>
        </div>
    </div>

    <button type="submit" class="btn btn-primary">Lưu Policy</button>
    <a href="policies.php" class="btn">Hủy</a>
</form>

<script>
function toggleTarget() {
    const type = document.querySelector('input[name="target_type"]:checked').value;
    document.getElementById('targetGroupBox').style.display = type === 'GROUP' ? 'block' : 'none';
    document.getElementById('targetDeviceBox').style.display = type === 'DEVICE' ? 'block' : 'none';
}
</script>

<?php require_once __DIR__ . '/../includes/layout_footer.php'; ?>