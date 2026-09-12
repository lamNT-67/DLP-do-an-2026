-- ========================================
-- DLP MANAGEMENT SERVER - DATABASE SCHEMA
-- ========================================

CREATE DATABASE IF NOT EXISTS dlp_system CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE dlp_system;

-- 1. Nhóm người dùng/máy
CREATE TABLE groups (
    id              INT PRIMARY KEY AUTO_INCREMENT,
    name            VARCHAR(100) NOT NULL UNIQUE,
    description     TEXT,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 2. Endpoint (máy cài agent)
CREATE TABLE endpoints (
    id              INT PRIMARY KEY AUTO_INCREMENT,
    hostname        VARCHAR(100) NOT NULL UNIQUE,
    username        VARCHAR(100),
    group_id        INT,
    api_token       VARCHAR(255) NOT NULL UNIQUE,
    agent_version   VARCHAR(20),
    status          ENUM('ONLINE','OFFLINE') DEFAULT 'OFFLINE',
    last_seen       DATETIME,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE SET NULL,
    INDEX idx_endpoints_group (group_id),
    INDEX idx_endpoints_status (status)
);

-- 3. Content rules (regex/dictionary)
CREATE TABLE content_rules (
    id              INT PRIMARY KEY AUTO_INCREMENT,
    rule_name       VARCHAR(100) NOT NULL,
    rule_type       ENUM('REGEX','DICTIONARY') NOT NULL,
    pattern         TEXT NOT NULL,
    category        ENUM('PII','FINANCE','INTERNAL_DOC') NOT NULL,
    severity        ENUM('LOW','MEDIUM','HIGH','CRITICAL') NOT NULL DEFAULT 'MEDIUM',
    is_active       BOOLEAN DEFAULT TRUE,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- 4. Policy rules (state theo exit point cho từng nhóm)
CREATE TABLE policy_rules (
    id                  INT PRIMARY KEY AUTO_INCREMENT,
    group_id            INT NOT NULL,
    exit_point_type     ENUM('USB','CLIPBOARD','NETWORK_WEB','NETWORK_SCP_SFTP','NETWORK_FTP','RDP') NOT NULL,
    state               ENUM('OPEN','MONITORED','CONTROLLED','BLOCKED') NOT NULL DEFAULT 'MONITORED',
    updated_at          DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    updated_by          VARCHAR(100),
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
    UNIQUE KEY uq_policy_group_exitpoint (group_id, exit_point_type)
);

-- 5. Liên kết policy - content rules (nhiều-nhiều)
CREATE TABLE policy_content_rules (
    policy_id           INT NOT NULL,
    content_rule_id     INT NOT NULL,
    PRIMARY KEY (policy_id, content_rule_id),
    FOREIGN KEY (policy_id) REFERENCES policy_rules(id) ON DELETE CASCADE,
    FOREIGN KEY (content_rule_id) REFERENCES content_rules(id) ON DELETE CASCADE
);

-- 6. USB whitelist
CREATE TABLE usb_whitelist (
    id              INT PRIMARY KEY AUTO_INCREMENT,
    serial_number   VARCHAR(100) NOT NULL UNIQUE,
    description     VARCHAR(200),
    group_id        INT,
    added_by        VARCHAR(100),
    added_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE SET NULL
);

-- 7. Network blacklist (domain/IP/port)
CREATE TABLE network_blacklist (
    id              INT PRIMARY KEY AUTO_INCREMENT,
    target_type     ENUM('DOMAIN','IP','PORT') NOT NULL,
    value           VARCHAR(255) NOT NULL,
    description     VARCHAR(200),
    is_active       BOOLEAN DEFAULT TRUE,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 8. Violation summary (dashboard riêng, không thay Wazuh)
CREATE TABLE violation_summary (
    id                  INT PRIMARY KEY AUTO_INCREMENT,
    endpoint_id         INT NOT NULL,
    exit_point_type     ENUM('USB','CLIPBOARD','NETWORK_WEB','NETWORK_SCP_SFTP','NETWORK_FTP','RDP') NOT NULL,
    policy_state        ENUM('MONITORED','CONTROLLED') NOT NULL,
    action_taken        ENUM('ALLOWED','LOGGED','BLOCKED_DELETE','BLOCKED_FIREWALL','BLOCKED_KILL') NOT NULL,
    file_path           VARCHAR(500),
    file_hash_sha256    VARCHAR(64),
    matched_rule_ids    VARCHAR(255),
    confidence_score    ENUM('LOW','MEDIUM','HIGH','CRITICAL'),
    destination_value   VARCHAR(255),
    process_name        VARCHAR(100),
    occurred_at         DATETIME NOT NULL,
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(id) ON DELETE CASCADE,
    INDEX idx_violation_endpoint (endpoint_id),
    INDEX idx_violation_time (occurred_at),
    INDEX idx_violation_action (action_taken)
);

-- 9. Admin (đăng nhập Web UI)
CREATE TABLE admins (
    id              INT PRIMARY KEY AUTO_INCREMENT,
    username        VARCHAR(100) NOT NULL UNIQUE,
    password_hash   VARCHAR(255) NOT NULL,
    full_name       VARCHAR(100),
    role            ENUM('SUPER_ADMIN','VIEWER') DEFAULT 'VIEWER',
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login      DATETIME
);

-- ========================================
-- SEED DATA MẪU (để test ngay)
-- ========================================

-- Admin mac dinh: username=admin, password=admin123
-- (hash bcrypt that, tuong thich voi ham password_verify() cua PHP)
INSERT INTO admins (username, password_hash, full_name, role) VALUES
('admin', '$2b$10$Q9hw.laI70K9INfrFgfGSesOVnY6VvOEQ81vUqvMnfDDQUko.s/gi', 'Quan tri vien', 'SUPER_ADMIN');

-- Nhóm mẫu
INSERT INTO groups (name, description) VALUES
('Kinh doanh', 'Nhan vien phong Kinh doanh'),
('IT', 'Nhan vien phong Ky thuat/IT'),
('Ke toan', 'Nhan vien phong Ke toan');

-- Endpoint mẫu (dùng để test Agent gọi API)
INSERT INTO endpoints (hostname, username, group_id, api_token) VALUES
('PC-KINHDOANH-01', 'nguyenvana', 1, 'test-token-kd-01'),
('PC-IT-01', 'tranvanb', 2, 'test-token-it-01');

-- Content rules mẫu
INSERT INTO content_rules (rule_name, rule_type, pattern, category, severity) VALUES
('PII_CCCD', 'REGEX', '\\b\\d{12}\\b', 'PII', 'HIGH'),
('PII_PHONE_VN', 'REGEX', '\\b(0[3|5|7|8|9])+([0-9]{8})\\b', 'PII', 'MEDIUM'),
('PII_EMAIL', 'REGEX', '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b', 'PII', 'LOW'),
('FINANCE_CREDIT_CARD', 'REGEX', '\\b(?:\\d[ -]*?){13,16}\\b', 'FINANCE', 'CRITICAL'),
('INTERNAL_LABEL', 'DICTIONARY', 'Mat,Tuyet mat,Noi bo,Confidential,Restricted', 'INTERNAL_DOC', 'HIGH');

-- Policy rules mẫu cho nhóm "Kinh doanh"
INSERT INTO policy_rules (group_id, exit_point_type, state, updated_by) VALUES
(1, 'USB', 'CONTROLLED', 'admin'),
(1, 'CLIPBOARD', 'CONTROLLED', 'admin'),
(1, 'NETWORK_WEB', 'MONITORED', 'admin'),
(1, 'NETWORK_SCP_SFTP', 'BLOCKED', 'admin');

-- Policy rules mẫu cho nhóm "IT"
INSERT INTO policy_rules (group_id, exit_point_type, state, updated_by) VALUES
(2, 'USB', 'MONITORED', 'admin'),
(2, 'CLIPBOARD', 'OPEN', 'admin'),
(2, 'NETWORK_WEB', 'CONTROLLED', 'admin'),
(2, 'NETWORK_SCP_SFTP', 'CONTROLLED', 'admin');

-- Gán content rules vào các policy CONTROLLED
INSERT INTO policy_content_rules (policy_id, content_rule_id)
SELECT id, 1 FROM policy_rules WHERE state = 'CONTROLLED';
INSERT INTO policy_content_rules (policy_id, content_rule_id)
SELECT id, 4 FROM policy_rules WHERE state = 'CONTROLLED';

-- Network blacklist mẫu
INSERT INTO network_blacklist (target_type, value, description) VALUES
('DOMAIN', 'drive.google.com', 'Google Drive upload'),
('DOMAIN', 'dropbox.com', 'Dropbox upload'),
('DOMAIN', 'wetransfer.com', 'WeTransfer upload'),
('PORT', '22', 'SSH/SCP/SFTP port');
