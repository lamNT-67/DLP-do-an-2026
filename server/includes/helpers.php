<?php
/**
 * Ham tien ich dung chung.
 */

// Sinh API token ngau nhien khi tao endpoint moi
function generate_api_token(): string {
    return bin2hex(random_bytes(24)); // chuoi hex 48 ky tu
}

// Escape output ra HTML de tranh XSS khi in du lieu tu DB ra trang
function h(?string $value): string {
    return htmlspecialchars($value ?? '', ENT_QUOTES, 'UTF-8');
}

// Class CSS cho badge theo state cua policy
function state_badge_class(string $state): string {
    return match ($state) {
        'OPEN'       => 'badge-open',
        'MONITORED'  => 'badge-monitored',
        'CONTROLLED' => 'badge-controlled',
        'BLOCKED'    => 'badge-blocked',
        default      => '',
    };
}

// Class CSS cho badge theo severity/confidence
function severity_badge_class(string $level): string {
    return match ($level) {
        'LOW'      => 'badge-low',
        'MEDIUM'   => 'badge-medium',
        'HIGH'     => 'badge-high',
        'CRITICAL' => 'badge-critical',
        default    => '',
    };
}

// Format datetime cho de doc
function format_datetime(?string $dt): string {
    if (!$dt) return '-';
    return date('d/m/Y H:i:s', strtotime($dt));
}
