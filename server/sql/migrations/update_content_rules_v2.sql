-- =====================================================================
-- Migration: cap nhat content rules + file types cho Content Inspection Engine v2
-- Chay 1 lan trong phpMyAdmin (tab SQL) tren database dlp_system.
--
-- Ly do:
--  * PII_CCCD cu (\b\d{12}\b) khop moi day 12 so  -> them dieu kien so 0 dau + so thu 4 (0-3);
--    engine con kiem tra ma tinh (001-096) phia agent.
--  * PII_PHONE_VN cu dung [3|5|7|8|9] (dau | bi hieu la ky tu) -> viet lai theo dau so nha mang.
--  * FINANCE_CREDIT_CARD: 13-19 so, engine kiem tra them thuat toan Luhn.
--  * INTERNAL_LABEL cu dung tu khong dau 1 tu ("Mat") -> khop nham "format", "mat"... ;
--    doi sang cum tu co dau (engine tu khop ca khi go khong dau voi cum >= 2 tu).
--  * File type: luon chan file database/backup va file thuc thi.
-- =====================================================================
USE dlp_system;
SET NAMES utf8mb4;

UPDATE content_rules SET pattern = '(?<!\\d)0\\d{2}[0-3]\\d{8}(?!\\d)'
WHERE rule_name = 'PII_CCCD';

UPDATE content_rules SET pattern = '(?<![\\d+])(?:\\+?84|0)(?:3[2-9]|5[25689]|7[06-9]|8[1-9]|9\\d)(?:[ .-]?\\d){7}(?!\\d)'
WHERE rule_name = 'PII_PHONE_VN';

UPDATE content_rules SET pattern = '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}'
WHERE rule_name = 'PII_EMAIL';

UPDATE content_rules SET pattern = '(?<!\\d)(?:\\d[ -]?){12,18}\\d(?!\\d)'
WHERE rule_name = 'FINANCE_CREDIT_CARD';

UPDATE content_rules SET pattern = 'Tuyệt mật,Tối mật,Tài liệu mật,Lưu hành nội bộ,Confidential,Strictly Confidential,Internal Use Only,Restricted'
WHERE rule_name = 'INTERNAL_LABEL';

-- Loai file luon chan (khong can quet noi dung).
-- Luu y: phai gan cac loai file nay vao policy (trang Policies) thi agent moi nhan duoc.
UPDATE dlp_file_types SET always_block_regardless_content = TRUE,
       description = 'File thuc thi Windows - luon chan'
WHERE extension = 'exe';

INSERT INTO dlp_file_types (extension, category, always_block_regardless_content, description) VALUES
('sql',    'OTHER',      TRUE, 'Dump/script database - luon chan'),
('bak',    'OTHER',      TRUE, 'File backup database - luon chan'),
('sqlite', 'OTHER',      TRUE, 'Database SQLite - luon chan'),
('mdb',    'OTHER',      TRUE, 'Database Access cu - luon chan'),
('accdb',  'OTHER',      TRUE, 'Database Access - luon chan'),
('msi',    'EXECUTABLE', TRUE, 'Bo cai Windows - luon chan')
ON DUPLICATE KEY UPDATE always_block_regardless_content = VALUES(always_block_regardless_content),
                        description = VALUES(description);
