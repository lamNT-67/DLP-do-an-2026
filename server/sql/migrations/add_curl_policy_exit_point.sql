-- Run manually on the selected DLP database. Append to each current enum so
-- existing labels and their order are preserved, including legacy values.
SET @curl_ddl = (
    SELECT CASE WHEN LOCATE('''CLIENT_CURL''', COLUMN_TYPE) > 0 THEN 'SELECT 1'
        ELSE CONCAT('ALTER TABLE dlp_policy_exit_points MODIFY COLUMN exit_point_type ',
                    LEFT(COLUMN_TYPE, CHAR_LENGTH(COLUMN_TYPE) - 1), ',''CLIENT_CURL'') NOT NULL') END
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'dlp_policy_exit_points'
        AND COLUMN_NAME = 'exit_point_type' AND DATA_TYPE = 'enum'
);
PREPARE curl_migration FROM @curl_ddl;
EXECUTE curl_migration;
DEALLOCATE PREPARE curl_migration;

SET @curl_ddl = (
    SELECT CASE WHEN LOCATE('''CLIENT_CURL''', COLUMN_TYPE) > 0 THEN 'SELECT 1'
        ELSE CONCAT('ALTER TABLE logs MODIFY COLUMN exit_point_type ',
                    LEFT(COLUMN_TYPE, CHAR_LENGTH(COLUMN_TYPE) - 1), ',''CLIENT_CURL'') NOT NULL') END
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'logs'
        AND COLUMN_NAME = 'exit_point_type' AND DATA_TYPE = 'enum'
);
PREPARE curl_migration FROM @curl_ddl;
EXECUTE curl_migration;
DEALLOCATE PREPARE curl_migration;
