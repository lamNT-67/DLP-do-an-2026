-- ========================================
-- DLP MANAGEMENT SERVER - SCHEMA v3
-- (Netwrix EPP-style: auto-registration, device management, tach PII rieng)
-- ========================================

CREATE DATABASE IF NOT EXISTS dlp_system CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE dlp_system;

-- 1. Nhom thiet bi
CREATE TABLE groups (
    id              INT PRIMARY KEY AUTO_INCREMENT,
    name            VARCHAR(100) NOT NULL UNIQUE,
    description     TEXT,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 2. ENROLLMENT KEYS - dung de Agent tu dang ky lan dau (thay the viec Admin tao tay endpoint)
CREATE TABLE enrollment_keys (
    id              INT PRIMARY KEY AUTO_INCREMENT,
    enrollment_key  VARCHAR(64) NOT NULL UNIQUE,
    description     VARCHAR(150),
    is_active       BOOLEAN DEFAULT TRUE,
    created_by      VARCHAR(100),
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 3. DEVICES - Agent tu dong them dong moi khi dang ky lan dau
CREATE TABLE devices (
    id                  INT PRIMARY KEY AUTO_INCREMENT,
    hostname            VARCHAR(100) NOT NULL UNIQUE,
    ip_address          VARCHAR(45),
    os_info             VARCHAR(150),
    username            VARCHAR(100),
    group_id            INT DEFAULT NULL,
    api_token           VARCHAR(255) NOT NULL UNIQUE,
    agent_version       VARCHAR(20),
    status              ENUM('ONLINE','OFFLINE') DEFAULT 'OFFLINE',
    enrolled_via_key_id INT DEFAULT NULL,
    first_seen          DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen           DATETIME,
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE SET NULL,
    FOREIGN KEY (enrolled_via_key_id) REFERENCES enrollment_keys(id) ON DELETE SET NULL,
    INDEX idx_devices_group (group_id),
    INDEX idx_devices_status (status)
);

-- 4. CONTENT RULES - rieng cho PII/Finance/Noi bo
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

-- 5. Master list loai file
CREATE TABLE dlp_file_types (
    id                                  INT PRIMARY KEY AUTO_INCREMENT,
    extension                           VARCHAR(20) NOT NULL UNIQUE,
    category                            ENUM('DOCUMENT','ARCHIVE','IMAGE','EXECUTABLE','OTHER') NOT NULL,
    always_block_regardless_content     BOOLEAN DEFAULT FALSE,
    description                         VARCHAR(150)
);

-- 6. DLP_POLICIES
CREATE TABLE dlp_policies (
    id                  INT PRIMARY KEY AUTO_INCREMENT,
    name                VARCHAR(150) NOT NULL,
    description         TEXT,
    target_type         ENUM('GROUP','DEVICE') NOT NULL,
    target_group_id     INT DEFAULT NULL,
    action              ENUM('BLOCK','REPORT_ONLY') NOT NULL DEFAULT 'REPORT_ONLY',
    is_active           BOOLEAN DEFAULT TRUE,
    created_by          VARCHAR(100),
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (target_group_id) REFERENCES groups(id) ON DELETE CASCADE
);

-- 7. Policy ap dung cho thiet bi cu the
CREATE TABLE dlp_policy_devices (
    policy_id       INT NOT NULL,
    device_id       INT NOT NULL,
    PRIMARY KEY (policy_id, device_id),
    FOREIGN KEY (policy_id) REFERENCES dlp_policies(id) ON DELETE CASCADE,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);

-- 8. Exit point duoc tick trong Policy
CREATE TABLE dlp_policy_exit_points (
    policy_id           INT NOT NULL,
    exit_point_type     ENUM('USB','CLIPBOARD','NETWORK_WEB','NETWORK_SCP_SFTP','NETWORK_FTP','RDP') NOT NULL,
    PRIMARY KEY (policy_id, exit_point_type),
    FOREIGN KEY (policy_id) REFERENCES dlp_policies(id) ON DELETE CASCADE
);

-- 9. File type duoc tick de block
CREATE TABLE dlp_policy_file_types (
    policy_id       INT NOT NULL,
    file_type_id    INT NOT NULL,
    PRIMARY KEY (policy_id, file_type_id),
    FOREIGN KEY (policy_id) REFERENCES dlp_policies(id) ON DELETE CASCADE,
    FOREIGN KEY (file_type_id) REFERENCES dlp_file_types(id) ON DELETE CASCADE
);

-- 10. Content rule (PII/Regex) gan vao Policy
CREATE TABLE dlp_policy_content_rules (
    policy_id           INT NOT NULL,
    content_rule_id     INT NOT NULL,
    PRIMARY KEY (policy_id, content_rule_id),
    FOREIGN KEY (policy_id) REFERENCES dlp_policies(id) ON DELETE CASCADE,
    FOREIGN KEY (content_rule_id) REFERENCES content_rules(id) ON DELETE CASCADE
);

-- 11. USB whitelist
CREATE TABLE usb_whitelist (
    id              INT PRIMARY KEY AUTO_INCREMENT,
    serial_number   VARCHAR(100) NOT NULL UNIQUE,
    description     VARCHAR(200),
    group_id        INT,
    added_by        VARCHAR(100),
    added_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE SET NULL
);

-- 12. Network blacklist
CREATE TABLE network_blacklist (
    id              INT PRIMARY KEY AUTO_INCREMENT,
    target_type     ENUM('DOMAIN','IP','PORT') NOT NULL,
    value           VARCHAR(255) NOT NULL,
    description     VARCHAR(200),
    is_active       BOOLEAN DEFAULT TRUE,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 13. LOGS - tab rieng
CREATE TABLE logs (
    id                  INT PRIMARY KEY AUTO_INCREMENT,
    device_id           INT NOT NULL,
    policy_id           INT DEFAULT NULL,
    exit_point_type     ENUM('USB','CLIPBOARD','NETWORK_WEB','NETWORK_SCP_SFTP','NETWORK_FTP','RDP') NOT NULL,
    action_taken        ENUM('ALLOWED','LOGGED','BLOCKED_DELETE','BLOCKED_FIREWALL','BLOCKED_KILL') NOT NULL,
    file_path           VARCHAR(500),
    file_hash_sha256    VARCHAR(64),
    matched_rule_ids    VARCHAR(255),
    confidence_score    ENUM('LOW','MEDIUM','HIGH','CRITICAL'),
    destination_value   VARCHAR(255),
    process_name        VARCHAR(100),
    occurred_at         DATETIME NOT NULL,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
    FOREIGN KEY (policy_id) REFERENCES dlp_policies(id) ON DELETE SET NULL,
    INDEX idx_logs_device (device_id),
    INDEX idx_logs_time (occurred_at),
    INDEX idx_logs_action (action_taken)
);

-- 14. Admin
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
-- SEED DATA MAU
-- ========================================

INSERT INTO admins (username, password_hash, full_name, role) VALUES
('admin', '$2b$10$Q9hw.laI70K9INfrFgfGSesOVnY6VvOEQ81vUqvMnfDDQUko.s/gi', 'Quan tri vien', 'SUPER_ADMIN');

INSERT INTO groups (name, description) VALUES
('Kinh doanh', 'Nhan vien phong Kinh doanh'),
('IT', 'Nhan vien phong Ky thuat/IT'),
('Ke toan', 'Nhan vien phong Ke toan');

INSERT INTO enrollment_keys (enrollment_key, description, created_by) VALUES
('DLP-ENROLL-DEMO-2026', 'Key mac dinh dung de test/demo do an', 'admin');

INSERT INTO content_rules (rule_name, rule_type, pattern, category, severity) VALUES
('PII_CCCD', 'REGEX', '\\b\\d{12}\\b', 'PII', 'HIGH'),
('PII_PHONE_VN', 'REGEX', '\\b(0[3|5|7|8|9])+([0-9]{8})\\b', 'PII', 'MEDIUM'),
('PII_EMAIL', 'REGEX', '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b', 'PII', 'LOW'),
('FINANCE_CREDIT_CARD', 'REGEX', '\\b(?:\\d[ -]*?){13,16}\\b', 'FINANCE', 'CRITICAL'),
('INTERNAL_LABEL', 'DICTIONARY', 'Mat,Tuyet mat,Noi bo,Confidential,Restricted', 'INTERNAL_DOC', 'HIGH');

INSERT INTO dlp_file_types (extension, category, always_block_regardless_content, description) VALUES
('docx', 'DOCUMENT', FALSE, 'Microsoft Word'),
('doc',  'DOCUMENT', FALSE, 'Microsoft Word (cu)'),
('xlsx', 'DOCUMENT', FALSE, 'Microsoft Excel'),
('xls',  'DOCUMENT', FALSE, 'Microsoft Excel (cu)'),
('pdf',  'DOCUMENT', FALSE, 'PDF'),
('txt',  'DOCUMENT', FALSE, 'Text thuan'),
('csv',  'DOCUMENT', FALSE, 'CSV du lieu bang'),
('pptx', 'DOCUMENT', FALSE, 'Microsoft PowerPoint'),
('zip',  'ARCHIVE',  TRUE,  'Nen ZIP - khong doc duoc noi dung, luon chan'),
('rar',  'ARCHIVE',  TRUE,  'Nen RAR - khong doc duoc noi dung, luon chan'),
('7z',   'ARCHIVE',  TRUE,  'Nen 7-Zip - khong doc duoc noi dung, luon chan'),
('jpg',  'IMAGE',    FALSE, 'Anh JPEG'),
('png',  'IMAGE',    FALSE, 'Anh PNG'),
('exe',  'EXECUTABLE', FALSE, 'File thuc thi Windows'),
('bat',  'EXECUTABLE', FALSE, 'Script batch'),
('ps1',  'EXECUTABLE', FALSE, 'Script PowerShell');

-- 2 thiet bi mau (mo phong da tung auto-register qua enrollment key)
INSERT INTO devices (hostname, ip_address, os_info, username, group_id, api_token, agent_version, status, enrolled_via_key_id, last_seen) VALUES
('PC-KINHDOANH-01', '192.168.1.101', 'Windows 11 Pro 23H2', 'nguyenvana', 1, 'test-token-kd-01', '1.0.0', 'ONLINE', 1, NOW()),
('PC-IT-01', '192.168.1.102', 'Windows 10 Pro 22H2', 'tranvanb', 2, 'test-token-it-01', '1.0.0', 'OFFLINE', 1, DATE_SUB(NOW(), INTERVAL 2 HOUR));

-- Policy mau: theo Nhom "Kinh doanh"
INSERT INTO dlp_policies (name, description, target_type, target_group_id, action, created_by) VALUES
('Chan du lieu PII/Tai chinh qua USB va Clipboard - Kinh doanh',
 'Ngan chan nhan vien Kinh doanh dua CCCD, so the tin dung ra ngoai qua USB hoac clipboard',
 'GROUP', 1, 'BLOCK', 'admin');

SET @policy1 = LAST_INSERT_ID();

INSERT INTO dlp_policy_exit_points (policy_id, exit_point_type) VALUES
(@policy1, 'USB'), (@policy1, 'CLIPBOARD');

INSERT INTO dlp_policy_file_types (policy_id, file_type_id)
SELECT @policy1, id FROM dlp_file_types WHERE extension IN ('docx','xlsx','pdf','csv','txt','zip','rar');

INSERT INTO dlp_policy_content_rules (policy_id, content_rule_id)
SELECT @policy1, id FROM content_rules WHERE rule_name IN ('PII_CCCD','FINANCE_CREDIT_CARD');

INSERT INTO network_blacklist (target_type, value, description) VALUES
('DOMAIN', 'drive.google.com', 'Google Drive upload'),
('DOMAIN', 'dropbox.com', 'Dropbox upload'),
('DOMAIN', 'wetransfer.com', 'WeTransfer upload'),
('PORT', '22', 'SSH/SCP/SFTP port');