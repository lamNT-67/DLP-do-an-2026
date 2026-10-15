# DLP Agent–Server API Contract (v2)

Tài liệu này mô tả API thực tế trên branch `fix/server-agent-api-validation`.

**Base URL (lab):** `http://<SERVER-IP>/dlp_server/api/`. Dùng HTTPS trong triển khai thực tế.

## Xác thực

- `agent_register.php`: xác thực bằng enrollment key trong JSON.
- Các endpoint còn lại: `Authorization: Bearer <api_token>`.
- Agent lưu token được cấp khi đăng ký; không đăng ký lại sau mỗi lần restart. Hostname trùng sẽ nhận HTTP 409.
- Gửi `Content-Type: application/json` cho tất cả POST.

## 1. POST agent_register.php

```json
{
  "hostname": "PC-LAB-01",
  "enrollment_key": "DLP-ENROLL-DEMO-2026",
  "ip_address": "192.168.1.20",
  "os_info": "Windows 10",
  "username": "labuser",
  "agent_version": "1.0.0"
}
```

Bắt buộc: `hostname`, `enrollment_key`. Thành công: **201 Created**:

```json
{
  "status": "registered",
  "device_id": 3,
  "api_token": "<new-device-token>",
  "note": "Unassigned until an admin assigns a group or device policy"
}
```

`enrollment_key` demo và token mẫu chỉ dành cho lab. Không đưa chúng vào bản build Agent triển khai thực tế.

## 2. GET agent_policy.php

Header: `Authorization: Bearer <api_token>`. Không cần query hostname.

```json
{
  "hostname": "PC-LAB-01",
  "is_assigned": false,
  "group_id": null,
  "applicable_policies": [
    {
      "policy_id": 1,
      "name": "USB lab policy",
      "action": "BLOCK",
      "exit_points": ["USB"],
      "file_types": [
        {"id": 1, "extension": "docx", "category": "DOCUMENT", "always_block_regardless_content": false}
      ],
      "content_rules": [
        {"id": 1, "rule_name": "PII_CCCD", "rule_type": "REGEX", "pattern": "\\b\\d{12}\\b", "category": "PII", "severity": "HIGH"}
      ],
      "allowed_locations": [],
      "allowed_files": []
    }
  ],
  "usb_whitelist": [],
  "network_blacklist": []
}
```

Ví dụ trên minh họa thiết bị **chưa gán Group nhưng có policy gán trực tiếp**. Giá trị thực tế phụ thuộc database.

`action`: `BLOCK` | `REPORT_ONLY`.

`exit_points`: `USB` | `CLIPBOARD` | `NETWORK_WEB` | `NETWORK_SCP_SFTP` | `NETWORK_FTP` | `RDP` | `SCREEN_CAPTURE`.

`is_assigned` hiện phản ánh việc có Group hay chưa, **không** phải có policy hay không. Với thiết bị chưa có Group, USB whitelist global và network blacklist vẫn được trả về.

**SCREEN_CAPTURE:** khi policy action là `BLOCK`, Agent cần chặn thao tác capture mà Agent hỗ trợ; với `REPORT_ONLY` chỉ ghi nhận. Không áp dụng kiểm tra file type/content rule cho exit point này. Server chỉ cấu hình và phân phối policy, không trực tiếp chặn ảnh chụp.

## 3. POST agent_heartbeat.php

Header: `Authorization: Bearer <api_token>`.

```json
{
  "hostname": "PC-LAB-01",
  "agent_version": "1.0.0",
  "ip_address": "192.168.1.20"
}
```

Bắt buộc: `hostname`. Response 200: `{"status":"ok"}`.

Khuyến nghị Agent gửi mỗi 30–60 giây. Trạng thái OFFLINE phụ thuộc logic timeout trên giao diện hoặc job server; heartbeat không tự đánh dấu thiết bị khác OFFLINE.

## 4. POST agent_report.php

Header: `Authorization: Bearer <api_token>`.

```json
{
  "hostname": "PC-LAB-01",
  "policy_id": null,
  "exit_point_type": "USB",
  "action_taken": "LOGGED",
  "file_path": "C:\\Lab\\sample.txt",
  "file_hash_sha256": null,
  "matched_rule_ids": [1],
  "confidence_score": "HIGH",
  "destination_value": "USB-SERIAL",
  "process_name": "explorer.exe",
  "occurred_at": "2026-10-15T10:00:00Z"
}
```

Bắt buộc: `hostname`, `exit_point_type`, `action_taken`, `occurred_at`.

`action_taken`: `ALLOWED` | `LOGGED` | `BLOCKED_DELETE` | `BLOCKED_FIREWALL` | `BLOCKED_KILL`.

`confidence_score`: `LOW` | `MEDIUM` | `HIGH` | `CRITICAL`.

`occurred_at` phải là ISO 8601 có timezone, ví dụ `2026-10-15T10:00:00Z` hoặc `2026-10-15T17:00:00+07:00`. Server chuẩn hóa về UTC trước khi lưu vào cột DATETIME.

`policy_id` có thể null; nếu có, phải là policy đang active và áp dụng cho thiết bị (theo Group hoặc Device). `matched_rule_ids` có thể là mảng số nguyên dương hoặc chuỗi `"1,2"`. SHA-256, nếu cung cấp, phải là 64 ký tự hex.

Thành công: **201 Created**, ví dụ `{"status":"ok","id":42}`.

## HTTP status

| Status | Ý nghĩa |
|---|---|
| 200 | GET policy hoặc heartbeat thành công |
| 201 | Đăng ký Agent hoặc tạo log thành công |
| 400 | JSON/field/enum/timestamp/policy không hợp lệ |
| 401 | Token không hợp lệ hoặc không khớp thiết bị |
| 403 | Enrollment key không hợp lệ |
| 405 | Sai HTTP method |
| 409 | Hostname đã đăng ký |
| 413 | Body vượt giới hạn 64 KiB |
| 415 | POST không gửi Content-Type application/json |
| 500 | Lỗi nội bộ; chi tiết chỉ ghi vào server error log |

## Lưu ý tích hợp

- Không còn sử dụng `policy_state` hoặc các trạng thái `OPEN/MONITORED/CONTROLLED/BLOCKED` của contract cũ.
- Khi mất kết nối, Agent phải có chiến lược cache policy và retry riêng; server hiện chưa có policy version/ETag.
- Các API chưa được kiểm thử end-to-end trên XAMPP/MySQL; cần chạy test với Agent trước khi triển khai.
