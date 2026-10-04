<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/helpers.php';

// Toggle active/inactive
if (isset($_GET['toggle'])) {
    $id = (int)$_GET['toggle'];
    $pdo->prepare("UPDATE dlp_policies SET is_active = NOT is_active WHERE id = ?")->execute([$id]);
    header('Location: policies.php');
    exit;
}

// Delete
if (isset($_GET['delete'])) {
    $id = (int)$_GET['delete'];
    $pdo->prepare("DELETE FROM dlp_policies WHERE id = ?")->execute([$id]);
    header('Location: policies.php');
    exit;
}

$sql = "
    SELECT
        p.*,
        g.name AS group_name,
        (SELECT COUNT(*) FROM dlp_policy_exit_points WHERE policy_id = p.id) AS exit_point_count,
        (SELECT COUNT(*) FROM dlp_policy_file_types WHERE policy_id = p.id) AS file_type_count,
        (SELECT COUNT(*) FROM dlp_policy_content_rules WHERE policy_id = p.id) AS rule_count,
        (SELECT COUNT(*) FROM dlp_policy_devices WHERE policy_id = p.id) AS device_target_count,
        (SELECT COUNT(*) FROM dlp_policy_exceptions WHERE policy_id = p.id) AS exception_count
    FROM dlp_policies p
    LEFT JOIN groups g ON p.target_group_id = g.id
    ORDER BY p.created_at DESC
";
$policies = $pdo->query($sql)->fetchAll();

$pageTitle = 'Policies';
require_once __DIR__ . '/../includes/layout_header.php';
?>

<div class="page-header">
    <h1>DLP Policies</h1>
    <a href="policy_form.php" class="btn btn-primary">+ Tạo Policy mới</a>
</div>

<table class="data-table">
    <thead>
        <tr>
            <th>Trạng thái</th>
            <th>Tên Policy</th>
            <th>Mục tiêu</th>
            <th>Action</th>
            <th>Exit Points</th>
            <th>File Types</th>
            <th>Content Rules</th>
            <th>Exceptions</th>
            <th>Cập nhật</th>
            <th>Hành động</th>
        </tr>
    </thead>
    <tbody>
        <?php foreach ($policies as $p): ?>
        <tr>
            <td>
                <a href="?toggle=<?= $p['id'] ?>">
                    <span class="status-dot <?= $p['is_active'] ? 'status-online' : 'status-offline' ?>"></span>
                </a>
            </td>
            <td><strong><?= h($p['name']) ?></strong><br><small style="color:#888;"><?= h($p['description']) ?></small></td>
            <td>
                <?php if ($p['target_type'] === 'GROUP'): ?>
                    Group: <?= h($p['group_name'] ?? '(đã xóa)') ?>
                <?php else: ?>
                    <?= $p['device_target_count'] ?> thiết bị cụ thể
                <?php endif; ?>
            </td>
            <td><span class="badge <?= action_badge_class($p['action']) ?>"><?= h($p['action']) ?></span></td>
            <td><?= $p['exit_point_count'] ?></td>
            <td><?= $p['file_type_count'] ?></td>
            <td><?= $p['rule_count'] ?></td>
            <td><?= $p['exception_count'] ?></td>
            <td><?= format_datetime($p['updated_at']) ?></td>
            <td>
                <a href="policy_form.php?id=<?= $p['id'] ?>">Edit</a> |
                <a href="?delete=<?= $p['id'] ?>" onclick="return confirm('Xóa policy này?')">Delete</a>
            </td>
        </tr>
        <?php endforeach; ?>
        <?php if (empty($policies)): ?>
        <tr><td colspan="10" style="text-align:center; color:#888;">Chưa có policy nào.</td></tr>
        <?php endif; ?>
    </tbody>
</table>

<?php require_once __DIR__ . '/../includes/layout_footer.php'; ?>