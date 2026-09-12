# API Contract — DLP System

Tai lieu nay la "hop dong giao tiep" giua Agent va DLP Management Server.
Nguoi lam Agent chi can doc file nay, KHONG can doc code PHP ben trong `/api/`.

Base URL (khi test trong mang LAN): `http://<IP-may-XAMPP>/dlp_server/api/`

---

## Xac thuc

Moi request (tru khi noi khac) phai gui header:

```
Authorization: Bearer <api_token>
```

`api_token` duoc Admin tao san cho tung endpoint trong trang `admin/endpoints.php`,
dua cho nguoi phu trach Agent dien vao file config cua Agent tren may do.

---

## 1. GET /agent_policy.php?hostname={hostname}

Agent goi dinh ky (khuyen nghi: moi 60 giay) de lay policy moi nhat.

**Request**
```
GET /api/agent_policy.php?hostname=PC-KINHDOANH-01
Authorization: Bearer test-token-kd-01
```

**Response 200 OK**
```json
{
    "group_name": "Kinh doanh",
    "policies": [
        {
            "exit_point_type": "USB",
            "state": "CONTROLLED",
            "content_rules": [
                {
                    "id": 1,
                    "rule_name": "PII_CCCD",
                    "rule_type": "REGEX",
                    "pattern": "\\b\\d{12}\\b",
                    "category": "PII",
                    "severity": "HIGH"
                }
            ]
        },
        { "exit_point_type": "CLIPBOARD", "state": "CONTROLLED", "content_rules": [] },
        { "exit_point_type": "NETWORK_WEB", "state": "MONITORED", "content_rules": [] },
        { "exit_point_type": "NETWORK_SCP_SFTP", "state": "BLOCKED", "content_rules": [] }
    ],
    "usb_whitelist": ["SN123456789"],
    "network_blacklist": [
        { "target_type": "DOMAIN", "value": "drive.google.com" },
        { "target_type": "PORT", "value": "22" }
    ]
}
```

**Cac gia tri enum can biet**
- `exit_point_type`: `USB` | `CLIPBOARD` | `NETWORK_WEB` | `NETWORK_SCP_SFTP` | `NETWORK_FTP` | `RDP`
- `state`: `OPEN` | `MONITORED` | `CONTROLLED` | `BLOCKED`
  - `OPEN` → Agent KHONG can chay watcher cho kenh nay (tiet kiem tai nguyen).
  - `MONITORED` → Agent van quet noi dung, luon CHO QUA, chi ghi log.
  - `CONTROLLED` → Agent quet noi dung, neu vi pham thi CHAN.
  - `BLOCKED` → Chan hoan toan, khong can quet noi dung.
- `content_rules` chi co du lieu khi state la `MONITORED` hoac `CONTROLLED`.
- `rule_type`: `REGEX` | `DICTIONARY` (voi DICTIONARY, `pattern` la chuoi tu khoa cach nhau boi dau phay, vi du `"Mat,Confidential,Noi bo"`)
- `severity`: `LOW` | `MEDIUM` | `HIGH` | `CRITICAL`

**Loi co the gap**
| Code | Y nghia |
|---|---|
| 400 | Thieu tham so `hostname` |
| 401 | Thieu header `Authorization` |
| 403 | `hostname` + token khong khop trong database |
| 500 | Loi server/database |

---

## 2. POST /agent_report.php

Agent goi moi khi co su kien tai exit point can ghi nhan (cho phep / canh bao / chan).

**Request**
```
POST /api/agent_report.php
Authorization: Bearer test-token-kd-01
Content-Type: application/json

{
    "hostname": "PC-KINHDOANH-01",
    "exit_point_type": "USB",
    "policy_state": "CONTROLLED",
    "action_taken": "BLOCKED_DELETE",
    "file_path": "D:\\bao_cao_khach_hang.xlsx",
    "file_hash_sha256": "a1b2c3d4...",
    "matched_rule_ids": [1, 4],
    "confidence_score": "HIGH",
    "destination_value": "SN987654321",
    "process_name": null,
    "occurred_at": "2026-08-28T10:15:32Z"
}
```

**Cac field bat buoc:** `hostname`, `exit_point_type`, `policy_state`, `action_taken`, `occurred_at`
**Cac field tuy chon (co the null/bo qua):** `file_path`, `file_hash_sha256`, `matched_rule_ids`, `confidence_score`, `destination_value`, `process_name`

**Ghi chu quan trong:**
- `matched_rule_ids` co the gui dang mang JSON `[1, 4]` HOAC chuoi `"1,4"` — server tu chuan hoa, khong bat buoc phai giong 1 kieu.
- `occurred_at` nen gui theo chuan ISO 8601 (`2026-08-28T10:15:32Z`), server tu convert sang dinh dang MySQL.
- `policy_state` chi nhan `MONITORED` hoac `CONTROLLED` (khong gui `OPEN`/`BLOCKED` vi 2 state nay khong can quet/log chi tiet).
- `action_taken`: `ALLOWED` | `LOGGED` | `BLOCKED_DELETE` | `BLOCKED_FIREWALL` | `BLOCKED_KILL`

**Response 200 OK**
```json
{ "status": "ok", "id": 42 }
```

**Loi co the gap**
| Code | Y nghia |
|---|---|
| 400 | Thieu field bat buoc, hoac JSON khong hop le |
| 401 | Thieu header `Authorization` |
| 403 | `hostname` + token khong khop |
| 405 | Goi sai method (phai la POST) |

---

## 3. POST /agent_heartbeat.php

Agent goi dinh ky (khuyen nghi: moi 30-60 giay) de bao con hoat dong.
Neu qua 5 phut khong co heartbeat, Server tu dong danh dau endpoint la `OFFLINE`
(hien thi tren Dashboard/trang Endpoints).

**Request**
```
POST /api/agent_heartbeat.php
Authorization: Bearer test-token-kd-01
Content-Type: application/json

{
    "hostname": "PC-KINHDOANH-01",
    "agent_version": "1.0.0"
}
```

**Response 200 OK**
```json
{ "status": "ok" }
```

---

## Cach lay API Token de test

1. Dang nhap trang Admin (`admin/login.php`), vao muc "Endpoints".
2. Tao endpoint moi (nhap hostname + chon nhom) → Server tu sinh token, hien thi 1 lan duy nhat.
3. Copy token do dien vao file config cua Agent (vi du `config.ini`).

**Du lieu mau da co san (seed trong schema.sql), dung ngay de test khong can tao moi:**

| hostname | group | api_token |
|---|---|---|
| PC-KINHDOANH-01 | Kinh doanh | `test-token-kd-01` |
| PC-IT-01 | IT | `test-token-it-01` |

---

## Vi du test nhanh bang cURL (truoc khi Agent that goi vao)

```bash
# Lay policy
curl "http://192.168.1.10/dlp_server/api/agent_policy.php?hostname=PC-KINHDOANH-01" \
     -H "Authorization: Bearer test-token-kd-01"

# Gui bao cao vi pham
curl -X POST "http://192.168.1.10/dlp_server/api/agent_report.php" \
     -H "Authorization: Bearer test-token-kd-01" \
     -H "Content-Type: application/json" \
     -d '{"hostname":"PC-KINHDOANH-01","exit_point_type":"USB","policy_state":"CONTROLLED","action_taken":"BLOCKED_DELETE","occurred_at":"2026-08-28T10:15:32Z"}'

# Heartbeat
curl -X POST "http://192.168.1.10/dlp_server/api/agent_heartbeat.php" \
     -H "Authorization: Bearer test-token-kd-01" \
     -H "Content-Type: application/json" \
     -d '{"hostname":"PC-KINHDOANH-01","agent_version":"1.0.0"}'
```

(Thay `192.168.1.10` bang IP LAN thuc te cua may chay XAMPP)
