<?php
if (session_status() !== PHP_SESSION_ACTIVE) session_start();
require_once __DIR__ . '/../config/database.php';
if (!isset($_SESSION['admin_id'])) { header('Location: login.php'); exit; }
$stmt=$pdo->prepare("SELECT id, username, full_name, role, is_active FROM admins WHERE id=?");
$stmt->execute([(int)$_SESSION['admin_id']]); $authenticatedAdmin=$stmt->fetch();
if (!$authenticatedAdmin || !(bool)$authenticatedAdmin['is_active']) {
    $_SESSION=[]; session_destroy(); header('Location: login.php?disabled=1'); exit;
}
$_SESSION['admin_username']=$authenticatedAdmin['username'];
$_SESSION['admin_full_name']=$authenticatedAdmin['full_name'];
$_SESSION['admin_role']=$authenticatedAdmin['role'];
function current_admin_name(){return $_SESSION['admin_full_name']??$_SESSION['admin_username']??'Admin';}
function current_admin_role(){return $_SESSION['admin_role']??'VIEWER';}
function is_super_admin(): bool{return current_admin_role()==='SUPER_ADMIN';}
function admin_can(string $module,string $action='view'): bool {
    if(is_super_admin()) return true;
    if(!in_array($action,['view','edit'],true)) return false;
    static $permissions=null;
    if($permissions===null){global $pdo;$s=$pdo->prepare("SELECT module_key,can_view,can_edit FROM admin_permissions WHERE admin_id=?");$s->execute([(int)$_SESSION['admin_id']]);$permissions=[];
        foreach($s->fetchAll() as $r)$permissions[$r['module_key']]=['view'=>(bool)$r['can_view'],'edit'=>(bool)$r['can_edit']];
    }
    if($action==='edit')return !empty($permissions[$module]['edit']);
    return !empty($permissions[$module]['view'])||!empty($permissions[$module]['edit']);
}
function require_super_admin(): void {if(!is_super_admin()){http_response_code(403);exit('Ban khong co quyen quan tri tai khoan.');}}
function enforce_admin_page_permission(): void {
    $page=basename($_SERVER['SCRIPT_NAME']??'');
    if(in_array($page,['login.php','logout.php'],true))return;
    if($page==='accounts.php'){require_super_admin();return;}
    $modules=['dashboard.php'=>'dashboard','devices.php'=>'devices','groups.php'=>'groups','policies.php'=>'policies','policy_form.php'=>'policies','content_rules.php'=>'content_rules','file_types.php'=>'file_types','usb_whitelist.php'=>'usb_whitelist','network_blacklist.php'=>'network_blacklist','logs.php'=>'logs','settings.php'=>'settings'];
    if(!isset($modules[$page]))return;
    $mutating=['delete','toggle','reset_password','activate','deactivate'];
    $edit=strtoupper($_SERVER['REQUEST_METHOD']??'GET')==='POST';
    foreach($mutating as $key)if(isset($_GET[$key]))$edit=true;
    $action=$edit?'edit':'view';
    if(!admin_can($modules[$page],$action)){http_response_code(403);exit($edit?'Tai khoan cua ban chi co quyen xem, khong co quyen chinh sua muc nay.':'Ban khong co quyen truy cap muc nay.');}
}
enforce_admin_page_permission();
