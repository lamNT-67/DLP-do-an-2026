# Simple Data Loss Prevention (DLP) System

Hệ thống **Data Loss Prevention (DLP)** phục vụ đồ án nghiên cứu và thử nghiệm kiểm soát dữ liệu trên máy Windows. Dự án gồm **Management Server** (PHP/MySQL), **Windows Agent** (Python), **Content Inspection Engine** và tích hợp **Wazuh SIEM** để tập trung cảnh báo.

> **Phạm vi:** proof of concept / môi trường lab. Hệ thống chưa đạt mức bảo vệ của DLP thương mại, chưa bảo đảm ngăn được mọi đường truyền dữ liệu. Nhánh `main` sử dụng **Agent Python**; Agent .NET V2 và extension thử nghiệm thuộc nhánh `agent-test`, **chưa được tích hợp sẵn vào `main`**.

## 1. Kiến trúc

```text
  Windows Endpoint
  ┌─────────────────────────────────────────────┐
  │ Python DLP Agent                            │
  │ - Network monitoring / policy enforcement   │
  │ - SCP/SFTP/FTP process monitoring           │
  │ - Clipboard & screenshot (user session)     │
  │ - Content Inspection Engine                 │
  └───────────────────┬─────────────────────────┘
                      │ HTTP JSON API
                      │ register / policy / heartbeat / report
                      ▼
  ┌─────────────────────────────────────────────┐
  │ DLP Management Server (PHP + MySQL)         │
  │ - Devices & Groups                          │
  │ - Policies, File Types, Content Rules       │
  │ - Exceptions, Whitelists / Blacklists       │
  │ - Event Logs                                │
  └───────────────────┬─────────────────────────┘
                      │ TCP Syslog (optional)
                      ▼
             Wazuh Manager → Indexer → Dashboard
```

**Luồng xử lý:** Admin tạo và kích hoạt policy → Agent đăng ký bằng enrollment key, nhận API token → Agent tải các policy áp dụng cho thiết bị/nhóm → module giám sát phát hiện hoạt động → Content Inspection Engine đánh giá → Agent thực hiện hành động phù hợp và báo cáo sự kiện → Server lưu MySQL, sau đó chuyển metadata sang Wazuh nếu đã cấu hình.

> Wazuh nhận log **từ DLP Server**, không phải trực tiếp từ Agent.

## 2. Chức năng

### Management Server

- Đăng ký và xác thực Agent; theo dõi thiết bị qua heartbeat.
- Quản lý **Devices**, **Groups**, **Policies**, **File Types**, **Content Rules**, **USB Whitelist**, **Network Blacklist** và **Logs**.
- Gán policy cho **một nhóm** hoặc **các thiết bị cụ thể**, kể cả thiết bị chưa thuộc group.
- Policy có trạng thái kích hoạt, hành động `BLOCK` hoặc `REPORT_ONLY`, exit points, loại file, content rules và ngoại lệ (allowed files / locations).
- Hiển thị tên các content rule khớp trong trang Logs.
- Lưu sự kiện DLP vào MySQL và chuyển tiếp Syslog sang Wazuh thông qua outbox có retry.

### Windows Agent trên `main`

| Thành phần | Mục đích | Trạng thái / giới hạn |
|---|---|---|
| `network_agent.py` | Theo dõi và áp dụng chính sách mạng/web | Không thay thế cho browser extension; không bảo đảm kiểm tra payload upload HTTPS |
| `sftp_scp_agent.py` | Theo dõi tiến trình SCP/SFTP/FTP, kiểm tra file được phát hiện | Cơ chế polling có nguy cơ chặn muộn; một số trường hợp tạo firewall rule ảnh hưởng toàn kết nối SSH/port |
| `clipboard_agent.py` | Kiểm soát clipboard và thao tác chụp màn hình | Phải chạy trong **phiên đăng nhập của người dùng**; installer hiện chưa tự cài module này thành service/task |
| `content_inspection.py` | Nhận diện loại file, trích xuất nội dung, so khớp Regex/Dictionary và đánh giá confidence | Khả năng trích xuất phụ thuộc định dạng và giới hạn đọc file |

Các exit point như `USB`, `RDP`, `BROWSER_CHROME`, `BROWSER_EDGE`, `BROWSER_FIREFOX`, `CLIENT_SCP`, `CLIENT_SFTP`, `CLIENT_FTP`, `CLIENT_WINSCP`, `CLIENT_FILEZILLA` có thể xuất hiện trong cấu hình Server, **nhưng không đồng nghĩa tất cả đều có module chặn hoàn chỉnh trên Agent Python `main`**.

### Content Inspection

Engine hỗ trợ kiểm tra theo đuôi/magic bytes, trích xuất nội dung ở các định dạng được triển khai (ví dụ TXT, CSV, PDF, DOCX, XLSX và một số loại archive), Regex và Dictionary; có validator cho một số dữ liệu PII và thang confidence `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`. Kết quả đánh giá nội bộ có thể là `ALLOW`, `LOG` hoặc `BLOCK`.

Khi kiểm thử thực tế, cần **chọn đúng file type trong policy** và **chọn đúng exit point mà Agent đang sử dụng** (ví dụ `NETWORK_SCP_SFTP` cho module Python SCP/SFTP).

## 3. Công nghệ

| Lớp | Công nghệ |
|---|---|
| Server | PHP 8+, Apache/XAMPP, MySQL/MariaDB, PDO |
| Agent | Python 3.10+, `psutil`, `requests`, `pypdf` |
| Windows service | NSSM |
| SIEM (tùy chọn) | Wazuh, TCP Syslog |

## 4. Cấu trúc repository

```text
DLP-do-an-2026/
├── README.md                  # Tổng quan và hướng dẫn nhanh
├── server/
│   ├── admin/                 # Trang quản trị
│   ├── api/                   # Agent REST/JSON API
│   ├── cli/wazuh_flush.php    # Retry gửi log sang Wazuh
│   ├── config/                # Database configuration
│   ├── includes/              # Auth, helpers, Wazuh forwarder
│   ├── sql/
│   │   ├── schema.sql
│   │   └── migrations/
│   ├── docs/
│   └── README.md
└── agent/
    ├── content_inspection.py
    ├── policy_client.py
    ├── policy_utils.py
    ├── network_agent.py
    ├── sftp_scp_agent.py
    ├── clipboard_agent.py
    ├── service/                # Windows installer/uninstaller
    ├── config.ini.example
    ├── requirements.txt
    └── README.md
```

## 5. Cài đặt DLP Server

**Yêu cầu:** Windows/XAMPP (hoặc hệ thống tương đương), Apache, PHP 8+ và MySQL/MariaDB.

1. Clone repository:
   ```powershell
   git clone https://github.com/lamNT-67/DLP-do-an-2026.git
   ```
2. Đặt thư mục `server` vào `C:\xampp\htdocs\dlp_server` (hoặc sử dụng alias/VirtualHost phù hợp).
3. Khởi động **Apache** và **MySQL** trong XAMPP.
4. Với database lab **mới**, import `server/sql/schema.sql` bằng phpMyAdmin. Với database **đã có dữ liệu**, dùng migration phù hợp trong `server/sql/migrations/`, **không import lại schema và seed**.
5. Kiểm tra kết nối database trong `server/config/database.php`.
6. Truy cập `http://<SERVER-IP>/dlp_server/` để mở giao diện Admin. Nếu triển khai thư mục/alias tên `server`, URL có thể là `http://<SERVER-IP>/server/`.

**Lưu ý bảo mật:** Schema/dữ liệu demo có thể chứa tài khoản hoặc khóa mẫu. Thay đổi credentials, enrollment key và token demo trước khi thử nghiệm trên mạng dùng chung. HTTP và Syslog TCP 514 không được mã hóa; chỉ dùng trong lab tin cậy hoặc bổ sung bảo vệ đường truyền.

Xem thêm: [Server README](server/README.md).

## 6. Cài đặt Agent Windows

**Yêu cầu:** Windows 10/11, Python 3.10+, quyền Administrator, kết nối đến DLP Server. Agent không cần cài XAMPP.

1. Trên DLP Web → **Settings**, lấy enrollment key.
2. Trên máy Windows Agent, clone/copy repo và vào:
   ```powershell
   cd DLP-do-an-2026\agent\service
   ```
3. Chạy `install.bat` bằng quyền Administrator (hoặc `install.ps1` qua PowerShell). Khi được hỏi, nhập:
   - **Server URL:** ví dụ `http://192.168.106.142/server/api` hoặc `http://<IP>/dlp_server/api` tùy cách triển khai.
   - **Hostname:** tên thiết bị đăng ký.
   - **Enrollment Key:** lấy từ Server Settings.
4. Installer tạo `C:\DLP\agent`, môi trường Python `C:\DLP\venv`, và hai service tự khởi động:
   - `DLPNetworkAgent`
   - `DLPSftpScpAgent`
5. Kiểm tra:
   ```powershell
   Get-Service DLPNetworkAgent, DLPSftpScpAgent
   Get-Content C:\ProgramData\DLP\logs\DLPSftpScpAgent.out.log -Tail 30
   ```
6. Trên DLP Web → **Devices**, kiểm tra thiết bị đăng ký/heartbeat, rồi **tạo và kích hoạt policy** áp dụng cho đúng thiết bị hoặc group.

Để test Clipboard/Screen Capture trên branch `main`, mở terminal **trong phiên người dùng đang đăng nhập** rồi chạy thủ công:
```powershell
cd C:\DLP\agent
C:\DLP\venv\Scripts\python.exe clipboard_agent.py
```

**Lưu ý:** Agent nhận policy theo chu kỳ; trạng thái heartbeat thành công chưa chứng minh đã có policy phù hợp. Không đăng tải `config.ini` chứa API token/enrollment key lên repository.

Xem thêm: [Agent README](agent/README.md).

## 7. Chính sách và kiểm thử

1. Vào **Policies → Tạo Policy**.
2. Chọn **Group** hoặc **Thiết bị cụ thể**.
3. Chọn `BLOCK` (chặn) hoặc `REPORT_ONLY` (chỉ theo dõi).
4. Chọn exit point, file types, content rules và ngoại lệ nếu cần.
5. **Đảm bảo đã tick “Kích hoạt policy”** trước khi lưu.
6. Tạo sự kiện thử nghiệm trên Agent và xem **Admin → Logs**.

Test riêng engine bằng file lab:

```powershell
C:\DLP\venv\Scripts\python.exe C:\DLP\agent\content_inspection.py C:\Lab\secret.txt
```

Lệnh trên chỉ kiểm tra engine với rule mặc định dành cho CLI; **không chứng minh Agent đang thực thi policy được cấp từ Server**.

Kiểm tra policy mà Server trả cho Agent (không in token):

```powershell
cd C:\DLP\agent
C:\DLP\venv\Scripts\python.exe -c "from policy_client import PolicyClient; import configparser,json; c=configparser.ConfigParser(); c.read('config.ini'); a=c['agent']; p=PolicyClient(a['server_url'],a['hostname'],a['api_token']); d=p.get_policy(); print(json.dumps(d.get('applicable_policies',[]) if d else None,indent=2,ensure_ascii=False))"
```

**Chú ý riêng với SCP/SFTP:** Test trên VM/lab. Nếu Agent chặn theo firewall port/IP thì SSH hoặc cả các lần truyền file sạch tiếp theo cũng có thể bị ảnh hưởng và không sinh thêm log file-level. Cơ chế quan sát tiến trình không bảo đảm chặn trước khi file đã truyền xong.

## 8. Tích hợp Wazuh SIEM (tùy chọn)

Luồng tích hợp: **Agent → DLP Server (MySQL + outbox) → Wazuh Manager (TCP Syslog) → Wazuh Dashboard**.

1. Trên DLP Server cũ, áp dụng hai migration:
   - `server/sql/migrations/add_wazuh_settings.sql`
   - `server/sql/migrations/add_wazuh_outbox.sql`
2. Trong DLP Web → **Settings → Wazuh SIEM Integration**, nhập **IP Wazuh Manager** và **TCP port 514**.
3. Trên máy Ubuntu Wazuh, thêm block sau bên trong `<ossec_config>` của `/var/ossec/etc/ossec.conf` (không thay block `secure` port 1514):
   ```xml
   <remote>
     <connection>syslog</connection>
     <port>514</port>
     <protocol>tcp</protocol>
     <allowed-ips>192.168.106.142</allowed-ips>
   </remote>
   ```
   Thay `allowed-ips` bằng **IP DLP Server** thực tế. Restart manager và xác minh listener:
   ```bash
   sudo systemctl restart wazuh-manager
   sudo ss -lntp | grep ':514'
   ```
4. Tạo sự kiện DLP mới rồi kiểm tra outbox trên MySQL:
   ```sql
   SELECT log_id, attempts, sent_at, last_error
   FROM dlp_wazuh_outbox ORDER BY log_id DESC LIMIT 10;
   ```
5. Cấu hình Windows Task Scheduler để định kỳ chạy `server/cli/wazuh_flush.php`, retry các sự kiện chưa gửi:
   ```powershell
   C:\xampp\php\php.exe C:\xampp\htdocs\dlp_server\cli\wazuh_flush.php
   ```
6. Tạo Wazuh custom decoder/rule nếu cần phân loại riêng DLP events; xem sự kiện trong **Threat Hunting → Events**. Có dữ liệu ở `sent_at` chỉ xác nhận ghi TCP, **không tự chứng minh Wazuh đã index hoặc alert**.

Hướng dẫn chi tiết: [Wazuh Configuration](server/docs/WAZUH_CONFIGURATION.md).

## 9. API chính

| Endpoint | Phương thức | Mục đích |
|---|---|---|
| `api/agent_register.php` | POST | Đăng ký thiết bị bằng enrollment key |
| `api/agent_policy.php` | GET | Lấy policy áp dụng cho thiết bị đã xác thực |
| `api/agent_heartbeat.php` | Agent heartbeat | Cập nhật trạng thái thiết bị |
| `api/agent_report.php` | POST | Nhận và lưu sự kiện DLP, queue gửi Wazuh |

Chi tiết hợp đồng API và payload: xem tài liệu trong [server/docs](server/docs/) cùng source code tương ứng.

## 10. Giới hạn và hướng phát triển

- Cần hoàn thiện cơ chế **block-before-transfer** cho SCP/SFTP/FTP, tránh chặn quá muộn hoặc tạo firewall rule làm gián đoạn toàn bộ SSH.
- Browser extension Chrome/Edge đang nằm ở nhánh thử nghiệm `agent-test`; muốn dùng cho Python Agent `main` cần triển khai local HTTP bridge tương ứng và tích hợp Content Inspection Engine.
- Clipboard/Screenshot cần tiến trình chạy trong phiên người dùng và cơ chế tự khởi động phù hợp.
- Các kênh USB, RDP, browser và các client truyền file cần kiểm chứng khả năng thực thi tương ứng; có exit point ở Server không có nghĩa đã chặn được.
- Hoàn thiện kiểm thử E2E, cấu hình HTTPS/TLS, quản lý secrets, giới hạn truy cập và audit logging trước khi triển khai ngoài môi trường lab.

---

**Mục tiêu đồ án:** minh họa quy trình quản lý policy, kiểm tra nội dung dữ liệu trên endpoint, phản ứng với hành vi vi phạm và tổng hợp cảnh báo trên hệ thống SIEM.