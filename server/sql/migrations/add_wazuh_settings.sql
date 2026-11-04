-- Store the destination for a future DLP -> Wazuh log forwarder.
-- This migration stores configuration only; no events are transmitted.
CREATE TABLE IF NOT EXISTS wazuh_settings (
    id TINYINT UNSIGNED NOT NULL PRIMARY KEY,
    siem_ip VARCHAR(45) NOT NULL,
    siem_port SMALLINT UNSIGNED NOT NULL DEFAULT 514,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
