# DLP Management Server

Server quản lý hệ thống Data Loss Prevention (DLP) phục vụ đồ án. Backend sử dụng PHP 8.1 trở lên, MySQL/MariaDB và giao diện quản trị chạy qua Apache/XAMPP. Agent giao tiếp với server bằng HTTP API dạng JSON.

> **Trạng thái:** bản demo/lab, chưa được harden để triển khai production. Chỉ dùng trong mạng thử nghiệm đáng tin cậy; không công khai API qua Internet khi chưa bật HTTPS, bảo vệ token và hoàn thiện kiểm soát truy cập.

## 1. Chức năng hiện có

- Agent tự đăng ký bằng enrollment key, nhận API token riêng; thiết bị mới ở trạng thái **Unassigned**.
- Admin quản lý thiết bị, nhóm, policy, content rules, loại file, USB whitelist, network blacklist và log.
- Policy nhắm tới **Group** hoặc **Device**; mỗi policy có action `BLOCK` hoặc `REPORT_ONLY`, các exit point, file types, content rules và exceptions.
- Agent lấy policy, gửi heartbeat và báo cáo sự kiện.

**Exit points trong schema** gồm `CLIENT_CURL` cho upload HTTP(S) qua `curl.exe`. Danh sách đầy đủ nằm trong hợp đồng API. [API Contract](docs/API_CONTRACT.md)

**Lưu ý:** Server phân phối policy và lưu log; khả năng phát hiện/chặn thực tế phụ thuộc vào Agent. Có khai báo exit point không đồng nghĩa Agent đã hỗ trợ chặn kênh đó.

## 2. Yêu cầu

- Apache, PHP 8.1 trở lên và PDO MySQL. API dùng `array_is_list()` để kiểm tra JSON.
- XAMPP phù hợp để chạy trên Windows trong môi trường lab.
- Máy Agent truy cập được địa chỉ IP và cổng Apache của server.

Khi chọn hệ quản trị cho lab, ghi rõ phiên bản MariaDB và PHP đã kiểm thử. Schema còn dùng tên bảng `groups` không đặt trong dấu nháy. Từ MySQL 8.0.2, tên này là từ khóa dành riêng, nên cần sửa cách trích dẫn tên bảng và kiểm thử import mới trước khi dùng MySQL 8. [Từ khóa MySQL](https://dev.mysql.com/doc/refman/8.0/en/keywords.html)

## 3. Cài đặt

1. Clone repository và đặt thư mục `server` tại `C:\xampp\htdocs\dlp_server` (hoặc cấu hình VirtualHost/alias tương đương).
2. Khởi động Apache và MySQL trong XAMPP.
3. Mở phpMyAdmin và import `sql/schema.sql`. Script tạo database `dlp_system`, bảng và dữ liệu demo. **Chỉ import vào database lab mới; script seed không được thiết kế để chạy lặp lại trên dữ liệu đang sử dụng.**
4. Kiểm tra `config/database.php`: host, database, username, password. Cấu hình hiện tại dùng `localhost`, `dlp_system`, `root`, mật khẩu rỗng theo XAMPP lab.
5. Mở `http://localhost/dlp_server/` để vào trang đăng nhập admin.

### Nâng cấp database hiện có cho CLIENT_CURL

Database tạo từ `sql/schema.sql` hiện tại đã có kênh này. Với database có dữ liệu, duyệt và chạy thử migration trên bản sao trước khi áp dụng thủ công. [Migration curl](sql/migrations/add_curl_policy_exit_point.sql)

- Sao lưu dữ liệu và dùng `SHOW CREATE TABLE` để kiểm tra `dlp_policy_exit_points` và `logs`. Hai cột `exit_point_type` phải là enum theo schema chuẩn, có `NOT NULL` và không có mặc định, chú thích hoặc charset/collation riêng cần giữ. Với schema đã tùy chỉnh, chuẩn bị câu lệnh ALTER giữ nguyên các thuộc tính trước khi nâng cấp.
- Hoàn tất các migration nền cần thiết trước khi thêm curl. Một số migration cũ thay toàn bộ danh sách enum nên có thể làm mất `CLIENT_CURL` nếu chạy lại sau đó. Bản dump cũ cũng có thể thiếu các cột mà API hiện tại yêu cầu.
- Chọn đúng database, dùng tài khoản có quyền ALTER và chạy toàn bộ script trong một phiên kết nối. Hai lệnh ALTER commit độc lập. Nếu lệnh thứ hai lỗi, kiểm tra cả hai cột rồi chạy lại sau khi xử lý lỗi. Script sẽ bỏ qua enum đã có `CLIENT_CURL`. Trên bản sao, xác nhận thứ tự và giá trị cũ được giữ, sau đó chạy lại để kiểm tra tính lặp lại.

**Cảnh báo:** Schema có sẵn tài khoản admin, enrollment key và API token mẫu. Hãy thay/thu hồi toàn bộ thông tin demo trước khi cho thiết bị thật kết nối. Không dùng tài khoản MySQL root không mật khẩu trong môi trường chia sẻ.

## 4. Cấu trúc quan trọng

```text
server/
├── index.php                 # Chuyển hướng tới admin/login.php
├── config/database.php       # Kết nối PDO MySQL
├── sql/schema.sql            # Schema và seed demo
├── includes/                 # Helper, xác thực và layout
├── admin/                    # Giao diện quản trị
├── api/
│   ├── agent_register.php    # Đăng ký Agent
│   ├── agent_policy.php      # Lấy policy
│   ├── agent_report.php      # Gửi log sự kiện
│   └── agent_heartbeat.php   # Cập nhật trạng thái Agent
└── docs/API_CONTRACT.md      # Tài liệu API (cần đồng bộ với code)
```

## 5. Luồng hoạt động

1. Admin tạo/cung cấp enrollment key hợp lệ.
2. Agent gửi `POST /api/agent_register.php` với hostname và enrollment key. Server tạo device chưa gán nhóm, trả về `device_id` và `api_token`.
3. Agent lưu API token an toàn; **không đăng ký lại ở mỗi lần khởi động**. Hiện tại hostname trùng trả HTTP 409, không cấp lại token.
4. Admin gán Group hoặc policy trực tiếp cho Device.
5. Agent gọi `GET /api/agent_policy.php` với Bearer token để nhận policy.
6. Agent định kỳ gọi heartbeat và gửi log sự kiện qua report API.

**Giới hạn hiện tại:** Hàm lấy policy trả kết quả rỗng sớm khi Device chưa có Group, nên policy gán trực tiếp cho Device chưa có Group sẽ không được trả về. Cần sửa trước khi dựa vào cơ chế gán trực tiếp.

## 6. API hiện tại (theo code)

Base URL ví dụ: `http://localhost/dlp_server/api`. Thay `localhost` bằng IP máy server khi Agent ở VM/máy khác. Dùng HTTPS khi triển khai ngoài lab.

### 6.1 POST /agent_register.php

Không yêu cầu Bearer token; xác thực bằng `enrollment_key`.

```json
{
  "hostname": "PC-LAB-01",
  "enrollment_key": "<enrollment-key>",
  "ip_address": "192.168.1.20",
  "os_info": "Windows 10",
  "username": "labuser",
  "agent_version": "1.0.0"
}
```

Bắt buộc: `hostname`, `enrollment_key`. Thành công trả `status: registered`, `device_id`, `api_token`. Lỗi thường gặp: 400 (JSON/field), 403 (key sai), 409 (hostname đã đăng ký), 405 (sai method).

### 6.2 GET /agent_policy.php

Header: `Authorization: Bearer <api_token>`.

Không yêu cầu query `hostname`; server xác định device bằng token. Response gồm `hostname`, `is_assigned`, `applicable_policies`, `usb_whitelist`, `network_blacklist` và `group_id` khi đã gán Group.

Mỗi phần tử `applicable_policies` có `policy_id`, `name`, `action` (`BLOCK` hoặc `REPORT_ONLY`), `exit_points`, `file_types`, `content_rules`, `allowed_locations`, `allowed_files`.

**Quan trọng:** Không sử dụng các trường `policies`, `state` (`OPEN/MONITORED/CONTROLLED/BLOCKED`) trong tài liệu cũ: chúng không phải response của implementation hiện tại.

### 6.3 POST /agent_heartbeat.php

Header: `Authorization: Bearer <api_token>`.

```json
{
  "hostname": "PC-LAB-01",
  "agent_version": "1.0.0",
  "ip_address": "192.168.1.20"
}
```

Bắt buộc: `hostname`. Server cập nhật `last_seen`, `status=ONLINE`, phiên bản Agent và IP; thành công trả `{"status":"ok"}`.

### 6.4 POST /agent_report.php

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
  "destination_value": "USB-SERIAL-EXAMPLE",
  "process_name": "explorer.exe",
  "occurred_at": "2026-10-15T10:00:00Z"
}
```

Bắt buộc: `hostname`, `exit_point_type`, `action_taken`, `occurred_at`. Thành công trả `status: ok` và ID log.

Danh sách `exit_point_type` và `action_taken` được mô tả trong hợp đồng API. [API Contract](docs/API_CONTRACT.md)

`confidence_score`: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.

`matched_rule_ids` chấp nhận mảng hoặc chuỗi phân tách bằng dấu phẩy. API kiểm tra enum, định dạng thời gian có múi giờ và quyền gán policy nếu Agent gửi `policy_id`.

## 7. Kiểm thử nhanh

Dùng PowerShell hoặc CMD có `curl.exe`:

```powershell
curl.exe -i "http://localhost/dlp_server/api/agent_policy.php" -H "Authorization: Bearer test-token-kd-01"
```

Token trên chỉ là dữ liệu demo từ `schema.sql`. Dùng Postman hoặc script Agent để gửi JSON cho ba API POST. Kiểm tra bản ghi trong `devices` và `logs` sau khi thử.

Đối với VM: xác định IP máy chạy XAMPP, bảo đảm Apache lắng nghe trên interface phù hợp, và chỉ mở firewall cho mạng lab/VM cần thiết. Không mở rộng cổng ra mạng Public chỉ để thử API.

## 8. Vấn đề cần khắc phục trước khi tích hợp hoàn chỉnh

- **P0:** Đồng bộ `docs/API_CONTRACT.md` với schema/API thực tế; sửa logic policy gán trực tiếp cho Device chưa có Group.
- **P0:** Không trả thông báo PDO exception ra client; bảo vệ token/enrollment key, HTTPS, giới hạn request.
- **P1:** Dùng xác thực Bearer thống nhất; heartbeat xác định device tồn tại bằng truy vấn riêng thay vì chỉ dựa vào `rowCount()`.
- **P1:** Validate JSON, hostname, enum, hash SHA-256, timestamp, kích thước request và `policy_id`; thống nhất UTC.
- **P1:** Thiết kế policy precedence khi nhiều policy cùng áp dụng, cơ chế version/update, và cách Agent xử lý khi mất kết nối.
- **P2:** Test tự động cho 4 API, logging lỗi phía server, cấu hình qua biến môi trường và cơ chế rotate/revoke token.

## 9. Phạm vi và lưu ý

Đây là README mô tả **implementation đang có trong repo**, không phải xác nhận rằng các API đã được kiểm thử end-to-end. Chưa có kết quả chạy thực tế trên Apache/MySQL/Agent. Cần kiểm tra cùng Agent trước khi tuyên bố các exit point được bảo vệ đầy đủ.
