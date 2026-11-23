-- Add process-name targets to the global network blacklist.
-- Run once on an existing DLP database; do not re-import schema.sql.
ALTER TABLE network_blacklist
    MODIFY COLUMN target_type ENUM('DOMAIN','IP','PORT','PROCESS') NOT NULL;
