-- Apply to an existing dlp_system database, without resetting data.
USE dlp_system;

CREATE TABLE IF NOT EXISTS dlp_policy_exceptions (
    id              INT PRIMARY KEY AUTO_INCREMENT,
    policy_id       INT NOT NULL,
    exception_type  ENUM('ALLOWED_LOCATION','ALLOWED_FILE') NOT NULL,
    value           VARCHAR(500) NOT NULL,
    FOREIGN KEY (policy_id) REFERENCES dlp_policies(id) ON DELETE CASCADE,
    INDEX idx_policy_exceptions_policy (policy_id)
);
