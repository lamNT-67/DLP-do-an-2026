<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/helpers.php';

$exitPointLabels = [
    'USB'               => 'USB / Removable Media',
    'CLIPBOARD'         => 'Clipboard',
    'NETWORK_WEB'       => 'Network - Web/Cloud',
    'NETWORK_SCP_SFTP'  => 'Network - SCP/SFTP',
    'NETWORK_FTP'       => 'Network - FTP',
    'RDP'               => 'Remote Desktop (RDP)',
];
$states = ['OPEN', 'MONITORED', 'CONTROLLED', 'BLOCKED'];

$groups = $pdo->query("SELECT id, name FROM groups ORDER BY name")->fetchAll();

$selectedGroupId = (int)($_GET['group_id'] ?? ($groups[0]['id'] ?? 0));

$message = '';

// --- Cap nhat state cho 1 policy ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'update_state') {
    $policyId = (int)$_POST['policy_id'];
    $newState = $_POST['state'];

    if (in_array($newState, $states)) {
        $pdo->prepare("UPDATE policy_rules SET state = ?, updated_by = ? WHERE id = ?")
            ->execute([$newState, current_admin_name(), $policyId]);
        $message = 'Da cap nhat trang thai.';
    }
    $selectedGroupId = (int)$_POST['group_id'];
}

// --- Gan/bo content rule cho 1 policy ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'update_rules') {
    $policyId = (int)$_POST['policy_id'];
    $selectedRuleIds = $_POST['rule_ids'] ?? []; // mang cac id duoc tick chon

    $pdo->prepare("DELETE FROM policy_content_rules WHERE policy_id = ?")->execute([$policyId]);
    $insert = $pdo->prepare("INSERT INTO policy_content_rules (policy_id, content_rule_id) VALUES (?, ?)");
    foreach ($selectedRuleIds as $ruleId) {
        $insert->execute([$policyId, (int)$ruleId]);
    }
    $message = 'Da cap nhat danh sach rule ap dung.';
    $selectedGroupId = (int)$_POST['group_id'];
}

// --- Lay policy cua nhom dang chon ---
$policies = [];
if ($selectedGroupId) {
    $stmt = $pdo->prepare("SELECT * FROM policy_rules WHERE group_id = ? ORDER BY FIELD(exit_point_type, 'USB','CLIPBOARD','NETWORK_WEB','NETWORK_SCP_SFTP','NETWORK_FTP','RDP')");
    $stmt->execute([$selectedGroupId]);
    $policies = $stmt->fetchAll();
}

$allContentRules = $pdo->query("SELECT * FROM content_rules WHERE is_active = 1 ORDER BY category, rule_name")->fetchAll();

// Lay san danh sach rule_id da gan cho tung policy, de tick san checkbox
$appliedRuleIds = [];
foreach ($policies as $p) {
    $stmt = $pdo->prepare("SELECT content_rule_id FROM policy_content_rules WHERE policy_id = ?");
    $stmt->execute([$p['id']]);
    $appliedRuleIds[$p['id']] = array_column($stmt->fetchAll(), 'content_rule_id');
}

$pageTitle = 'Policy Exit Point';
$activeMenu = 'policy';
require __DIR__ . '/../includes/layout_header.php';
?>

<?php if ($message): ?>
    <div class="success-msg"><?= h($message) ?></div>
<?php endif; ?>

<div class="card">
    <h2>Chon nhom</h2>
    <form method="GET">
        <div class="form-group" style="max-width:300px">
            <select name="group_id" onchange="this.form.submit()">
                <?php foreach ($groups as $g): ?>
                    <option value="<?= (int)$g['id'] ?>" <?= $g['id'] == $selectedGroupId ? 'selected' : '' ?>>
                        <?= h($g['name']) ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </div>
    </form>
</div>

<?php if (empty($policies)): ?>
    <div class="card"><p>Nhom nay chua co policy nao. Vao trang "Nhom nguoi dung" de tao nhom moi (policy mac dinh se tu tao).</p></div>
<?php endif; ?>

<?php foreach ($policies as $p): ?>
    <div class="card">
        <h2>
            <?= h($exitPointLabels[$p['exit_point_type']] ?? $p['exit_point_type']) ?>
            &nbsp;<span class="badge <?= state_badge_class($p['state']) ?>"><?= h($p['state']) ?></span>
        </h2>

        <!-- Form doi state -->
        <form method="POST" style="display:flex; gap:10px; align-items:center; margin-bottom:16px;">
            <input type="hidden" name="action" value="update_state">
            <input type="hidden" name="group_id" value="<?= (int)$selectedGroupId ?>">
            <input type="hidden" name="policy_id" value="<?= (int)$p['id'] ?>">
            <select name="state">
                <?php foreach ($states as $s): ?>
                    <option value="<?= $s ?>" <?= $p['state'] === $s ? 'selected' : '' ?>><?= $s ?></option>
                <?php endforeach; ?>
            </select>
            <button type="submit" class="btn btn-primary btn-sm">Cap nhat trang thai</button>
        </form>

        <?php if (in_array($p['state'], ['MONITORED', 'CONTROLLED'])): ?>
            <!-- Form chon content rules ap dung -->
            <form method="POST">
                <input type="hidden" name="action" value="update_rules">
                <input type="hidden" name="group_id" value="<?= (int)$selectedGroupId ?>">
                <input type="hidden" name="policy_id" value="<?= (int)$p['id'] ?>">
                <p style="font-size:13px; color:#616e7c; margin-bottom:8px;">
                    Chon cac Content Rule se duoc quet khi exit point nay o trang thai MONITORED/CONTROLLED:
                </p>
                <table>
                    <thead><tr><th></th><th>Ten rule</th><th>Loai</th><th>Danh muc</th><th>Muc do</th></tr></thead>
                    <tbody>
                    <?php foreach ($allContentRules as $r): ?>
                        <tr>
                            <td>
                                <input type="checkbox" name="rule_ids[]" value="<?= (int)$r['id'] ?>"
                                    <?= in_array($r['id'], $appliedRuleIds[$p['id']] ?? []) ? 'checked' : '' ?>>
                            </td>
                            <td><?= h($r['rule_name']) ?></td>
                            <td><?= h($r['rule_type']) ?></td>
                            <td><?= h($r['category']) ?></td>
                            <td><span class="badge <?= severity_badge_class($r['severity']) ?>"><?= h($r['severity']) ?></span></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
                <button type="submit" class="btn btn-primary btn-sm" style="margin-top:10px;">Luu danh sach rule</button>
            </form>
        <?php else: ?>
            <p style="font-size:13px; color:#616e7c;">
                Trang thai <strong><?= h($p['state']) ?></strong> khong can content rule
                (OPEN = khong giam sat, BLOCKED = chan hoan toan khong can quet noi dung).
            </p>
        <?php endif; ?>
    </div>
<?php endforeach; ?>

<?php require __DIR__ . '/../includes/layout_footer.php'; ?>
