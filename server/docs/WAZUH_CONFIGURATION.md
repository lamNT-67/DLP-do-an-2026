# Wazuh SIEM destination configuration (Phase 1)

This phase adds an IP + port configuration form in Server **Admin > Settings**. It does not send DLP logs to Wazuh yet, does not test connectivity and does not modify the endpoint Agent.

## Existing MySQL database
Execute `server/sql/migrations/add_wazuh_settings.sql` once in phpMyAdmin, while using the same `dlp_system` database as `server/config/database.php`:

```sql
USE dlp_system;
CREATE TABLE IF NOT EXISTS wazuh_settings (
    id TINYINT UNSIGNED NOT NULL PRIMARY KEY,
    siem_ip VARCHAR(45) NOT NULL,
    siem_port SMALLINT UNSIGNED NOT NULL DEFAULT 514,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

A fresh database initialized with the current `server/sql/schema.sql` already includes this table. Without migrating an existing database, opening the updated Settings page can fail with a missing-table database error.

## Using the UI
1. Deploy `main` version of `server/admin/settings.php`.
2. Login as an admin and open `Settings`.
3. Enter the **SIEM Server IP** (IPv4 or IPv6) and port (1-65535), then click **Luu cau hinh Wazuh**.
4. Reload Settings and verify values remain saved.

Storage is single-row `wazuh_settings` with `id=1`, `siem_ip`, `siem_port` and `updated_at`; update occurs via prepared SQL query and input validation.

## Future log forwarding
For future integration, decide the receiving transport **TCP or UDP syslog** (or another supported receiver), and configure the receiving side appropriately. The SIEM receiver port is **not necessarily** the Wazuh Agent enrollment port or the Wazuh Dashboard port. Port **514** in the empty-form default is only a placeholder convention for syslog, not confirmation the SIEM listens there. Do not send events to a port just because Wazuh is installed.

The future component should read persisted settings and forward DLP events from the Server (e.g., as structured JSON/syslog) with retries, authentication/transport protection where appropriate, logging and a bounded queue. This phase has no sending, no queue, no connectivity test, and no enable switch.
