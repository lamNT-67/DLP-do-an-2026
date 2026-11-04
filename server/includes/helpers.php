<?php

function generate_token(int $bytes = 24): string {
    return bin2hex(random_bytes($bytes));
}

function h(?string $value): string {
    return htmlspecialchars($value ?? '', ENT_QUOTES, 'UTF-8');
}

function action_badge_class(string $action): string {
    return match ($action) {
        'BLOCK'        => 'badge-blocked',
        'REPORT_ONLY'  => 'badge-monitored',
        default        => '',
    };
}

function severity_badge_class(string $level): string {
    return match ($level) {
        'LOW'      => 'badge-low',
        'MEDIUM'   => 'badge-medium',
        'HIGH'     => 'badge-high',
        'CRITICAL' => 'badge-critical',
        default    => '',
    };
}

function status_dot_class(string $status): string {
    return $status === 'ONLINE' ? 'dot-online' : 'dot-offline';
}

function format_datetime(?string $dt): string {
    if (!$dt) return '-';
    return date('d/m/Y H:i:s', strtotime($dt));
}
/**
 * Log timestamps are stored as UTC in a timezone-less MySQL DATETIME column.
 * Parse them explicitly as UTC, then render in Vietnam local time (UTC+07).
 * Do not modify stored values, otherwise exports/correlation would drift.
 */
function format_log_datetime(?string $dt): string {
    if (!$dt) return '-';
    try {
        $utc = new DateTimeImmutable($dt, new DateTimeZone('UTC'));
        return $utc->setTimezone(new DateTimeZone('Asia/Ho_Chi_Minh'))
            ->format('d/m/Y H:i:s');
    } catch (Throwable $e) {
        return '-';
    }
}
