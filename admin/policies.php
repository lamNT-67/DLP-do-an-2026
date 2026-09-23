<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/helpers.php';

if (isset($_GET['delete'])) {
    $pdo->prepare("DELETE FROM dlp_policies WHERE id = ?")->execute([(int)$_GET['delete']]);
    header('Location: policies.php');
    exit;
}

if (isset($_GET['toggle'])) {
    $pdo->prepare("UPDATE dlp_policies SET is_active = NOT is_active WHERE id = ?")->execute([(int)$_GET['toggle']]);
    header('Location: policies.php');
    exit;
}

$policies = $pdo->query("
    SELECT
        p.*,
        g.name AS group_name,
        (SELECT COUNT(*) FROM dlp_policy_exit_points WHERE policy_id = p.id) AS exit_point_count,
        (SELECT COUNT(*) FROM dlp_policy_file_types WHERE policy_id = p.id) AS file_type_count,
        (SELECT COUNT(*) FROM dlp_policy_content_rules WHERE policy_id = p.id) AS rule_count,
        (SELECT COUNT(*) FROM dlp_policy_devices WHERE policy_id = p.id) AS device_target_count
    FROM dlp_policies p
    LEFT JOIN groups g ON p.target_group_id = g.id
    ORDER BY p.created_at DESC
")->fetchAll();

$exitPointsByPolicy = [];
$rows = $pdo->query("SELECT policy_id, exit_point_type FROM dlp_policy_exit_points")->fetchAll();
foreach ($rows as $r) {
    $exitPointsByPolicy[$r['policy_id']][] = $r['exit_point_type'];
}

$pageTitle = 'DLP Policies';
$activeMenu = 'policies';
require __DIR__ . '/../includes/layout_header.php';
?>

<div class="card" style="display:flex; justify-content:space-between; align-items:center;">
    <p style="font-size:13px; color:#616e7c;">
        Moi Policy: tick Exit Point -> tick File Type can block -> gan PII/Content Rules -> chon hanh dong.
    </p>
    <a href="policy_form.php" class="btn btn-primary">+ Tao Policy moi</a>
</div>

<div class="card">
    <h2>Danh sach Policy (<?= count($policies) ?>)</h2>
    <table>
        <thead>
        <tr>
            <th>Ten Policy</th><th>Ap dung cho</th><th>Exit Points</th>
            <th>File Types</th><th>Content Rules</th><th>Hanh dong</th><th>Trang thai</th><th>Hanh dong</th>
        </tr>
        </thead>
        <tbody>
        <?php if (empty($policies)): ?>
            <tr><td colspan="8">Chua co Policy nao.</td></tr>
        <?php endif; ?>
        <?php foreach ($policies as $p): ?>
            <tr>
                <td>
                    <strong><?= h($p['name']) ?></strong><br>
                    <span style="font-size:12px; color:#9aa5b1;"><?= h($p['description']) ?></span>
                </td>
                <td>
                    <?php if ($p['target_type'] === 'GROUP'): ?>
                        Group: <strong><?= h($p['group_name'] ?? '(da xoa)') ?></strong>
                    <?php else: ?>
                        <?= (int)$p['device_target_count'] ?> thiet bi cu the
                    <?php endif; ?>
                </td>
                <td>
                    <?php foreach ($exitPointsByPolicy[$p['id']] ?? [] as $ep): ?>
                        <span class="badge badge-controlled" style="margin-bottom:2px; display:inline-block;"><?= h($ep) ?></span>
                    <?php endforeach; ?>
                    <?php if (empty($exitPointsByPolicy[$p['id']])): ?>-<?php endif; ?>
                </td>
                <td><?= (int)$p['file_type_count'] ?> loai</td>
                <td><?= (int)$p['rule_count'] ?> rule</td>
                <td><span class="badge <?= action_badge_class($p['action']) ?>"><?= h($p['action']) ?></span></td>
                <td><?= $p['is_active'] ? 'Dang bat' : 'Da tat' ?></td>
                <td>
                    <a href="policy_form.php?id=<?= (int)$p['id'] ?>" class="btn btn-secondary btn-sm">Sua</a>
                    <a href="policies.php?toggle=<?= (int)$p['id'] ?>" class="btn btn-secondary btn-sm">
                        <?= $p['is_active'] ? 'Tat' : 'Bat' ?>
                    </a>
                    <a href="policies.php?delete=<?= (int)$p['id'] ?>" class="btn btn-danger btn-sm"
                       onclick="return confirm('Xoa Policy nay?')">Xoa</a>
                </td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
</div>

<?php require __DIR__ . '/../includes/layout_footer.php'; ?>