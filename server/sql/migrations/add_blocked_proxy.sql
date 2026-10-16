-- Run once against existing dlp_system database before using HTTP proxy logging.
ALTER TABLE logs
  MODIFY COLUMN action_taken ENUM(
    'ALLOWED','LOGGED','BLOCKED_DELETE','BLOCKED_FIREWALL','BLOCKED_KILL','BLOCKED_PROXY'
  ) NOT NULL;
