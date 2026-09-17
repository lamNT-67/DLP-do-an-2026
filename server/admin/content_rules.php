<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/helpers.php';

$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'add') {
    $ruleName = trim($_POST['rule_name'] ?? '');
    $ruleType = $_POST['rule_type'] ?? 'REGEX';
    $pattern = trim($_POST['pattern'] ?? '');
    $category = $_POST['category'] ?? 'PII';
    $severity = $_POST['severity'] ?? 'MEDIUM';

    if ($ruleName !== '' && $pattern !== '') {
        // Neu la REGEX, kiem tra pattern hop le truoc khi luu (tranh loi khi Agent chay regex sai)
        $isValid = true;
        if ($ruleType === 'REGEX') {
            $isValid = @preg_match('/' . $pattern . '/', '') !== false;
        }

        if ($isValid) {
            $stmt = $pdo->prepare("INSERT INTO content_rules (rule_name, rule_type, pattern, category, severity) VALUES (?, ?, ?, ?, ?)");
            $stmt->execute([$ruleName, $ruleType, $pattern, $category, $severity]);
            $message = 'Da them rule moi.';
        } else {
            $message = 'Loi: Regex pattern khong hop le, vui long kiem tra lai.';
        }
    }
}

if (isset($_GET['toggle'])) {
    $pdo->prepare("UPDATE content_rules SET is_active = NOT is_active WHERE id = ?")->execute([(int)$_GET['toggle']]);
    header('Location: content_rules.php');
    exit;
}

if (isset($_GET['delete'])) {
    $pdo->prepare("DELETE FROM content_rules WHERE id = ?")->execute([(int)$_GET['delete']]);
    header('Location: content_rules.php');
    exit;
}

$rules = $pdo->query("SELECT * FROM content_rules ORDER BY category, rule_name")->fetchAll();

$pageTitle = 'Content Rules';
$activeMenu = 'content_rules';
require __DIR__ . '/../includes/layout_header.php';
?>

<?php if ($message): ?>
    <div class="success-msg"><?= h($message) ?></div>
<?php endif; ?>

<div class="card">
    <h2>Them Content Rule moi</h2>
    <form method="POST">
        <input type="hidden" name="action" value="add">
        <div class="form-group">
            <label>Ten rule</label>
            <input type="text" name="rule_name" placeholder="VD: PII_CCCD" required>
        </div>
        <div class="form-group">
            <label>Loai</label>
            <select name="rule_type">
                <option value="REGEX">REGEX</option>
                <option value="DICTIONARY">DICTIONARY (danh sach tu khoa, cach nhau boi dau phay)</option>
            </select>
        </div>
        <div class="form-group">
            <label>Pattern</label>
            <textarea name="pattern" placeholder="VD: \b\d{12}\b  hoac  Mat,Confidential,Noi bo" required></textarea>
        </div>
        <div class="form-group">
            <label>Danh muc</label>
            <select name="category">
                <option value="PII">PII</option>
                <option value="FINANCE">FINANCE</option>
                <option value="INTERNAL_DOC">INTERNAL_DOC</option>
            </select>
        </div>
        <div class="form-group">
            <label>Muc do nghiem trong</label>
            <select name="severity">
                <option value="LOW">LOW</option>
                <option value="MEDIUM" selected>MEDIUM</option>
                <option value="HIGH">HIGH</option>
                <option value="CRITICAL">CRITICAL</option>
            </select>
        </div>
        <button type="submit" class="btn btn-primary">Them rule</button>
    </form>
</div>

<div class="card">
    <h2>Danh sach Content Rules (<?= count($rules) ?>)</h2>
    <table>
        <thead>
        <tr><th>Ten rule</th><th>Loai</th><th>Pattern</th><th>Danh muc</th><th>Muc do</th><th>Trang thai</th><th>Hanh dong</th></tr>
        </thead>
        <tbody>
        <?php foreach ($rules as $r): ?>
            <tr>
                <td><?= h($r['rule_name']) ?></td>
                <td><?= h($r['rule_type']) ?></td>
                <td style="font-family:monospace; font-size:12px; max-width:250px; word-break:break-all;"><?= h($r['pattern']) ?></td>
                <td><?= h($r['category']) ?></td>
                <td><span class="badge <?= severity_badge_class($r['severity']) ?>"><?= h($r['severity']) ?></span></td>
                <td><?= $r['is_active'] ? 'Dang bat' : 'Da tat' ?></td>
                <td>
                    <a href="content_rules.php?toggle=<?= (int)$r['id'] ?>" class="btn btn-secondary btn-sm">
                        <?= $r['is_active'] ? 'Tat' : 'Bat' ?>
                    </a>
                    <a href="content_rules.php?delete=<?= (int)$r['id'] ?>" class="btn btn-danger btn-sm"
                       onclick="return confirm('Xoa rule nay?')">Xoa</a>
                </td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
</div>

<?php require __DIR__ . '/../includes/layout_footer.php'; ?>
