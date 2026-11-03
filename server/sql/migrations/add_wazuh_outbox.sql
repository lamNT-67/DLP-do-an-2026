-- Apply after add_wazuh_settings.sql. Existing DLP logs remain unchanged.
CREATE TABLE IF NOT EXISTS dlp_wazuh_outbox (
    log_id INT NOT NULL PRIMARY KEY,
    attempts INT UNSIGNED NOT NULL DEFAULT 0,
    next_attempt_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    locked_until DATETIME NULL,
    sent_at DATETIME NULL,
    last_error VARCHAR(255) NULL,
    CONSTRAINT fk_dlp_wazuh_log FOREIGN KEY (log_id) REFERENCES logs(id) ON DELETE CASCADE,
    INDEX idx_wazuh_outbox_due (sent_at, next_attempt_at, locked_until)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
