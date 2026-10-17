-- Run once against an existing MySQL database before enabling browser event logs.
ALTER TABLE logs MODIFY COLUMN action_taken
 ENUM('ALLOWED','LOGGED','BLOCKED_DELETE','BLOCKED_FIREWALL','BLOCKED_KILL','BLOCKED_PROXY','BLOCKED_BROWSER') NOT NULL;
