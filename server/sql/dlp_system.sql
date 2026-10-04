-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Oct 04, 2026 at 04:57 PM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.0.30

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `dlp_system`
--

-- --------------------------------------------------------

--
-- Table structure for table `admins`
--

CREATE TABLE `admins` (
  `id` int(11) NOT NULL,
  `username` varchar(100) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `full_name` varchar(100) DEFAULT NULL,
  `role` enum('SUPER_ADMIN','VIEWER') DEFAULT 'VIEWER',
  `created_at` datetime DEFAULT current_timestamp(),
  `last_login` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `admins`
--

INSERT INTO `admins` (`id`, `username`, `password_hash`, `full_name`, `role`, `created_at`, `last_login`) VALUES
(1, 'admin', '$2b$10$Q9hw.laI70K9INfrFgfGSesOVnY6VvOEQ81vUqvMnfDDQUko.s/gi', 'Quan tri vien', 'SUPER_ADMIN', '2026-09-23 21:29:17', '2026-10-03 21:54:18');

-- --------------------------------------------------------

--
-- Table structure for table `content_rules`
--

CREATE TABLE `content_rules` (
  `id` int(11) NOT NULL,
  `rule_name` varchar(100) NOT NULL,
  `rule_type` enum('REGEX','DICTIONARY') NOT NULL,
  `pattern` text NOT NULL,
  `category` enum('PII','FINANCE','INTERNAL_DOC') NOT NULL,
  `severity` enum('LOW','MEDIUM','HIGH','CRITICAL') NOT NULL DEFAULT 'MEDIUM',
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` datetime DEFAULT current_timestamp(),
  `updated_at` datetime DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `content_rules`
--

INSERT INTO `content_rules` (`id`, `rule_name`, `rule_type`, `pattern`, `category`, `severity`, `is_active`, `created_at`, `updated_at`) VALUES
(1, 'PII_CCCD', 'REGEX', '\\b\\d{12}\\b', 'PII', 'HIGH', 1, '2026-09-23 21:29:17', '2026-09-23 21:29:17'),
(2, 'PII_PHONE_VN', 'REGEX', '\\b(0[3|5|7|8|9])+([0-9]{8})\\b', 'PII', 'MEDIUM', 1, '2026-09-23 21:29:17', '2026-09-23 21:29:17'),
(3, 'PII_EMAIL', 'REGEX', '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b', 'PII', 'LOW', 1, '2026-09-23 21:29:17', '2026-09-23 21:29:17'),
(5, 'INTERNAL_LABEL', 'DICTIONARY', 'Mat,Tuyet mat,Noi bo,Confidential,Restricted', 'INTERNAL_DOC', 'HIGH', 1, '2026-09-23 21:29:17', '2026-09-23 21:29:17');

-- --------------------------------------------------------

--
-- Table structure for table `devices`
--

CREATE TABLE `devices` (
  `id` int(11) NOT NULL,
  `hostname` varchar(100) NOT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `os_info` varchar(150) DEFAULT NULL,
  `username` varchar(100) DEFAULT NULL,
  `group_id` int(11) DEFAULT NULL,
  `api_token` varchar(255) NOT NULL,
  `agent_version` varchar(20) DEFAULT NULL,
  `status` enum('ONLINE','OFFLINE') DEFAULT 'OFFLINE',
  `enrolled_via_key_id` int(11) DEFAULT NULL,
  `first_seen` datetime DEFAULT current_timestamp(),
  `last_seen` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `devices`
--

INSERT INTO `devices` (`id`, `hostname`, `ip_address`, `os_info`, `username`, `group_id`, `api_token`, `agent_version`, `status`, `enrolled_via_key_id`, `first_seen`, `last_seen`) VALUES
(1, 'PC-KINHDOANH-01', '192.168.1.101', 'Windows 11 Pro 23H2', 'nguyenvana', 1, 'test-token-kd-01', '1.0.0', 'OFFLINE', 1, '2026-09-23 21:29:17', '2026-09-23 21:29:17'),
(2, 'PC-IT-01', '192.168.1.102', 'Windows 10 Pro 22H2', 'tranvanb', 2, 'test-token-it-01', '1.0.0', 'OFFLINE', 1, '2026-09-23 21:29:17', '2026-09-23 19:29:17');

-- --------------------------------------------------------

--
-- Table structure for table `dlp_file_types`
--

CREATE TABLE `dlp_file_types` (
  `id` int(11) NOT NULL,
  `extension` varchar(20) NOT NULL,
  `category` enum('DOCUMENT','ARCHIVE','IMAGE','EXECUTABLE','OTHER') NOT NULL,
  `always_block_regardless_content` tinyint(1) DEFAULT 0,
  `description` varchar(150) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `dlp_file_types`
--

INSERT INTO `dlp_file_types` (`id`, `extension`, `category`, `always_block_regardless_content`, `description`) VALUES
(1, 'docx', 'DOCUMENT', 0, 'Microsoft Word'),
(2, 'doc', 'DOCUMENT', 0, 'Microsoft Word (cu)'),
(3, 'xlsx', 'DOCUMENT', 0, 'Microsoft Excel'),
(4, 'xls', 'DOCUMENT', 0, 'Microsoft Excel (cu)'),
(5, 'pdf', 'DOCUMENT', 0, 'PDF'),
(6, 'txt', 'DOCUMENT', 0, 'Text thuan'),
(7, 'csv', 'DOCUMENT', 0, 'CSV du lieu bang'),
(8, 'pptx', 'DOCUMENT', 0, 'Microsoft PowerPoint'),
(9, 'zip', 'ARCHIVE', 1, 'Nen ZIP - khong doc duoc noi dung, luon chan'),
(10, 'rar', 'ARCHIVE', 1, 'Nen RAR - khong doc duoc noi dung, luon chan'),
(11, '7z', 'ARCHIVE', 1, 'Nen 7-Zip - khong doc duoc noi dung, luon chan'),
(12, 'jpg', 'IMAGE', 0, 'Anh JPEG'),
(13, 'png', 'IMAGE', 0, 'Anh PNG'),
(14, 'exe', 'EXECUTABLE', 0, 'File thuc thi Windows'),
(15, 'bat', 'EXECUTABLE', 0, 'Script batch'),
(16, 'ps1', 'EXECUTABLE', 0, 'Script PowerShell');

-- --------------------------------------------------------

--
-- Table structure for table `dlp_policies`
--

CREATE TABLE `dlp_policies` (
  `id` int(11) NOT NULL,
  `name` varchar(150) NOT NULL,
  `description` text DEFAULT NULL,
  `target_type` enum('GROUP','DEVICE') NOT NULL,
  `target_group_id` int(11) DEFAULT NULL,
  `action` enum('BLOCK','REPORT_ONLY') NOT NULL DEFAULT 'REPORT_ONLY',
  `is_active` tinyint(1) DEFAULT 1,
  `created_by` varchar(100) DEFAULT NULL,
  `created_at` datetime DEFAULT current_timestamp(),
  `updated_at` datetime DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `dlp_policies`
--

INSERT INTO `dlp_policies` (`id`, `name`, `description`, `target_type`, `target_group_id`, `action`, `is_active`, `created_by`, `created_at`, `updated_at`) VALUES
(1, 'Chan du lieu PII/Tai chinh qua USB va Clipboard - Kinh doanh', 'Ngan chan nhan vien Kinh doanh dua CCCD, so the tin dung ra ngoai qua USB hoac clipboard', 'GROUP', 1, 'BLOCK', 1, 'admin', '2026-09-23 21:29:17', '2026-09-23 21:29:17');

-- --------------------------------------------------------

--
-- Table structure for table `dlp_policy_content_rules`
--

CREATE TABLE `dlp_policy_content_rules` (
  `policy_id` int(11) NOT NULL,
  `content_rule_id` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `dlp_policy_content_rules`
--

INSERT INTO `dlp_policy_content_rules` (`policy_id`, `content_rule_id`) VALUES
(1, 1);

-- --------------------------------------------------------

--
-- Table structure for table `dlp_policy_devices`
--

CREATE TABLE `dlp_policy_devices` (
  `policy_id` int(11) NOT NULL,
  `device_id` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `dlp_policy_exceptions`
--

CREATE TABLE `dlp_policy_exceptions` (
  `id` int(11) NOT NULL,
  `policy_id` int(11) NOT NULL,
  `exception_type` enum('ALLOWED_LOCATION','ALLOWED_FILE') NOT NULL,
  `value` varchar(500) NOT NULL,
  `description` varchar(200) DEFAULT NULL,
  `created_at` datetime DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `dlp_policy_exit_points`
--

CREATE TABLE `dlp_policy_exit_points` (
  `policy_id` int(11) NOT NULL,
  `exit_point_type` enum('USB','CLIPBOARD','NETWORK_WEB','NETWORK_SCP_SFTP','NETWORK_FTP','RDP','EMAIL_CLIENT','CLOUD_SYNC_FOLDER') NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `dlp_policy_exit_points`
--

INSERT INTO `dlp_policy_exit_points` (`policy_id`, `exit_point_type`) VALUES
(1, 'USB'),
(1, 'CLIPBOARD');

-- --------------------------------------------------------

--
-- Table structure for table `dlp_policy_file_types`
--

CREATE TABLE `dlp_policy_file_types` (
  `policy_id` int(11) NOT NULL,
  `file_type_id` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `dlp_policy_file_types`
--

INSERT INTO `dlp_policy_file_types` (`policy_id`, `file_type_id`) VALUES
(1, 1),
(1, 3),
(1, 5),
(1, 6),
(1, 7),
(1, 9),
(1, 10);

-- --------------------------------------------------------

--
-- Table structure for table `enrollment_keys`
--

CREATE TABLE `enrollment_keys` (
  `id` int(11) NOT NULL,
  `enrollment_key` varchar(64) NOT NULL,
  `description` varchar(150) DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `created_by` varchar(100) DEFAULT NULL,
  `created_at` datetime DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `enrollment_keys`
--

INSERT INTO `enrollment_keys` (`id`, `enrollment_key`, `description`, `is_active`, `created_by`, `created_at`) VALUES
(1, 'DLP-ENROLL-DEMO-2026', 'Key mac dinh dung de test/demo do an', 1, 'admin', '2026-09-23 21:29:17');

-- --------------------------------------------------------

--
-- Table structure for table `groups`
--

CREATE TABLE `groups` (
  `id` int(11) NOT NULL,
  `name` varchar(100) NOT NULL,
  `description` text DEFAULT NULL,
  `created_at` datetime DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `groups`
--

INSERT INTO `groups` (`id`, `name`, `description`, `created_at`) VALUES
(1, 'Kinh doanh', 'Nhan vien phong Kinh doanh', '2026-09-23 21:29:17'),
(2, 'IT', 'Nhan vien phong Ky thuat/IT', '2026-09-23 21:29:17');

-- --------------------------------------------------------

--
-- Table structure for table `logs`
--

CREATE TABLE `logs` (
  `id` int(11) NOT NULL,
  `device_id` int(11) NOT NULL,
  `policy_id` int(11) DEFAULT NULL,
  `exit_point_type` enum('USB','CLIPBOARD','NETWORK_WEB','NETWORK_SCP_SFTP','NETWORK_FTP','RDP','EMAIL_CLIENT','CLOUD_SYNC_FOLDER') NOT NULL,
  `action_taken` enum('ALLOWED','LOGGED','BLOCKED_DELETE','BLOCKED_FIREWALL','BLOCKED_KILL') NOT NULL,
  `file_path` varchar(500) DEFAULT NULL,
  `file_hash_sha256` varchar(64) DEFAULT NULL,
  `matched_rule_ids` varchar(255) DEFAULT NULL,
  `confidence_score` enum('LOW','MEDIUM','HIGH','CRITICAL') DEFAULT NULL,
  `destination_value` varchar(255) DEFAULT NULL,
  `process_name` varchar(100) DEFAULT NULL,
  `occurred_at` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `network_blacklist`
--

CREATE TABLE `network_blacklist` (
  `id` int(11) NOT NULL,
  `target_type` enum('DOMAIN','IP','PORT') NOT NULL,
  `value` varchar(255) NOT NULL,
  `description` varchar(200) DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` datetime DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `network_blacklist`
--

INSERT INTO `network_blacklist` (`id`, `target_type`, `value`, `description`, `is_active`, `created_at`) VALUES
(1, 'DOMAIN', 'drive.google.com', 'Google Drive upload', 1, '2026-09-23 21:29:17'),
(2, 'DOMAIN', 'dropbox.com', 'Dropbox upload', 1, '2026-09-23 21:29:17'),
(3, 'DOMAIN', 'wetransfer.com', 'WeTransfer upload', 1, '2026-09-23 21:29:17'),
(4, 'PORT', '22', 'SSH/SCP/SFTP port', 1, '2026-09-23 21:29:17');

-- --------------------------------------------------------

--
-- Table structure for table `usb_whitelist`
--

CREATE TABLE `usb_whitelist` (
  `id` int(11) NOT NULL,
  `serial_number` varchar(100) NOT NULL,
  `description` varchar(200) DEFAULT NULL,
  `group_id` int(11) DEFAULT NULL,
  `added_by` varchar(100) DEFAULT NULL,
  `added_at` datetime DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Indexes for dumped tables
--

--
-- Indexes for table `admins`
--
ALTER TABLE `admins`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`);

--
-- Indexes for table `content_rules`
--
ALTER TABLE `content_rules`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `devices`
--
ALTER TABLE `devices`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `hostname` (`hostname`),
  ADD UNIQUE KEY `api_token` (`api_token`),
  ADD KEY `enrolled_via_key_id` (`enrolled_via_key_id`),
  ADD KEY `idx_devices_group` (`group_id`),
  ADD KEY `idx_devices_status` (`status`);

--
-- Indexes for table `dlp_file_types`
--
ALTER TABLE `dlp_file_types`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `extension` (`extension`);

--
-- Indexes for table `dlp_policies`
--
ALTER TABLE `dlp_policies`
  ADD PRIMARY KEY (`id`),
  ADD KEY `target_group_id` (`target_group_id`);

--
-- Indexes for table `dlp_policy_content_rules`
--
ALTER TABLE `dlp_policy_content_rules`
  ADD PRIMARY KEY (`policy_id`,`content_rule_id`),
  ADD KEY `content_rule_id` (`content_rule_id`);

--
-- Indexes for table `dlp_policy_devices`
--
ALTER TABLE `dlp_policy_devices`
  ADD PRIMARY KEY (`policy_id`,`device_id`),
  ADD KEY `device_id` (`device_id`);

--
-- Indexes for table `dlp_policy_exceptions`
--
ALTER TABLE `dlp_policy_exceptions`
  ADD PRIMARY KEY (`id`),
  ADD KEY `policy_id` (`policy_id`);

--
-- Indexes for table `dlp_policy_exit_points`
--
ALTER TABLE `dlp_policy_exit_points`
  ADD PRIMARY KEY (`policy_id`,`exit_point_type`);

--
-- Indexes for table `dlp_policy_file_types`
--
ALTER TABLE `dlp_policy_file_types`
  ADD PRIMARY KEY (`policy_id`,`file_type_id`),
  ADD KEY `file_type_id` (`file_type_id`);

--
-- Indexes for table `enrollment_keys`
--
ALTER TABLE `enrollment_keys`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `enrollment_key` (`enrollment_key`);

--
-- Indexes for table `groups`
--
ALTER TABLE `groups`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `name` (`name`);

--
-- Indexes for table `logs`
--
ALTER TABLE `logs`
  ADD PRIMARY KEY (`id`),
  ADD KEY `policy_id` (`policy_id`),
  ADD KEY `idx_logs_device` (`device_id`),
  ADD KEY `idx_logs_time` (`occurred_at`),
  ADD KEY `idx_logs_action` (`action_taken`);

--
-- Indexes for table `network_blacklist`
--
ALTER TABLE `network_blacklist`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `usb_whitelist`
--
ALTER TABLE `usb_whitelist`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `serial_number` (`serial_number`),
  ADD KEY `group_id` (`group_id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `admins`
--
ALTER TABLE `admins`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `content_rules`
--
ALTER TABLE `content_rules`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- AUTO_INCREMENT for table `devices`
--
ALTER TABLE `devices`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- AUTO_INCREMENT for table `dlp_file_types`
--
ALTER TABLE `dlp_file_types`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=17;

--
-- AUTO_INCREMENT for table `dlp_policies`
--
ALTER TABLE `dlp_policies`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `dlp_policy_exceptions`
--
ALTER TABLE `dlp_policy_exceptions`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `enrollment_keys`
--
ALTER TABLE `enrollment_keys`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `groups`
--
ALTER TABLE `groups`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- AUTO_INCREMENT for table `logs`
--
ALTER TABLE `logs`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `network_blacklist`
--
ALTER TABLE `network_blacklist`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5;

--
-- AUTO_INCREMENT for table `usb_whitelist`
--
ALTER TABLE `usb_whitelist`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `devices`
--
ALTER TABLE `devices`
  ADD CONSTRAINT `devices_ibfk_1` FOREIGN KEY (`group_id`) REFERENCES `groups` (`id`) ON DELETE SET NULL,
  ADD CONSTRAINT `devices_ibfk_2` FOREIGN KEY (`enrolled_via_key_id`) REFERENCES `enrollment_keys` (`id`) ON DELETE SET NULL;

--
-- Constraints for table `dlp_policies`
--
ALTER TABLE `dlp_policies`
  ADD CONSTRAINT `dlp_policies_ibfk_1` FOREIGN KEY (`target_group_id`) REFERENCES `groups` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `dlp_policy_content_rules`
--
ALTER TABLE `dlp_policy_content_rules`
  ADD CONSTRAINT `dlp_policy_content_rules_ibfk_1` FOREIGN KEY (`policy_id`) REFERENCES `dlp_policies` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `dlp_policy_content_rules_ibfk_2` FOREIGN KEY (`content_rule_id`) REFERENCES `content_rules` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `dlp_policy_devices`
--
ALTER TABLE `dlp_policy_devices`
  ADD CONSTRAINT `dlp_policy_devices_ibfk_1` FOREIGN KEY (`policy_id`) REFERENCES `dlp_policies` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `dlp_policy_devices_ibfk_2` FOREIGN KEY (`device_id`) REFERENCES `devices` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `dlp_policy_exceptions`
--
ALTER TABLE `dlp_policy_exceptions`
  ADD CONSTRAINT `dlp_policy_exceptions_ibfk_1` FOREIGN KEY (`policy_id`) REFERENCES `dlp_policies` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `dlp_policy_exit_points`
--
ALTER TABLE `dlp_policy_exit_points`
  ADD CONSTRAINT `dlp_policy_exit_points_ibfk_1` FOREIGN KEY (`policy_id`) REFERENCES `dlp_policies` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `dlp_policy_file_types`
--
ALTER TABLE `dlp_policy_file_types`
  ADD CONSTRAINT `dlp_policy_file_types_ibfk_1` FOREIGN KEY (`policy_id`) REFERENCES `dlp_policies` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `dlp_policy_file_types_ibfk_2` FOREIGN KEY (`file_type_id`) REFERENCES `dlp_file_types` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `logs`
--
ALTER TABLE `logs`
  ADD CONSTRAINT `logs_ibfk_1` FOREIGN KEY (`device_id`) REFERENCES `devices` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `logs_ibfk_2` FOREIGN KEY (`policy_id`) REFERENCES `dlp_policies` (`id`) ON DELETE SET NULL;

--
-- Constraints for table `usb_whitelist`
--
ALTER TABLE `usb_whitelist`
  ADD CONSTRAINT `usb_whitelist_ibfk_1` FOREIGN KEY (`group_id`) REFERENCES `groups` (`id`) ON DELETE SET NULL;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
