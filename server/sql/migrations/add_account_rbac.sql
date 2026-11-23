-- Account management and per-module RBAC.
ALTER TABLE admins
    ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT TRUE AFTER role;

CREATE TABLE IF NOT EXISTS admin_permissions (
    admin_id INT NOT NULL,
    module_key VARCHAR(50) NOT NULL,
    can_view BOOLEAN NOT NULL DEFAULT FALSE,
    can_edit BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (admin_id, module_key),
    CONSTRAINT fk_admin_permissions_admin
        FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Preserve access for existing VIEWER accounts: view-only across current modules.
INSERT INTO admin_permissions (admin_id, module_key, can_view, can_edit)
SELECT a.id, modules.module_key, 1, 0
FROM admins a
CROSS JOIN (
    SELECT 'dashboard' AS module_key UNION ALL
    SELECT 'devices' UNION ALL SELECT 'groups' UNION ALL
    SELECT 'policies' UNION ALL SELECT 'content_rules' UNION ALL
    SELECT 'file_types' UNION ALL SELECT 'usb_whitelist' UNION ALL
    SELECT 'network_blacklist' UNION ALL SELECT 'logs' UNION ALL
    SELECT 'settings'
) AS modules
WHERE a.role = 'VIEWER'
ON DUPLICATE KEY UPDATE can_view = VALUES(can_view);
