# DLP Management Server — Huong dan cai dat (XAMPP)

## 1. Yeu cau
- XAMPP (Apache + MySQL + PHP >= 8.0, vi co dung `match()` trong helpers.php)

## 2. Cac buoc cai dat

### Buoc 1 — Copy thu muc du an
Copy toan bo thu muc `dlp_server/` vao:
```
C:\xampp\htdocs\dlp_server\
```

### Buoc 2 — Tao database
1. Mo XAMPP Control Panel, Start **Apache** va **MySQL**.
2. Mo trinh duyet, vao `http://localhost/phpmyadmin`.
3. Vao tab **SQL**, mo file `sql/schema.sql`, copy toan bo noi dung, dan vao o SQL, bam **Go**.
   - Script se tu tao database `dlp_system`, toan bo bang, va du lieu mau (2 endpoint test, 3 nhom, 5 content rule...).

### Buoc 3 — Kiem tra ket noi
Mo file `config/database.php`, kiem tra lai:
```php
$user = 'root';
$pass = '';   // neu XAMPP cua ban co dat mat khau MySQL thi sua lai o day
```

### Buoc 4 — Truy cap trang Admin
Mo trinh duyet: `http://localhost/dlp_server/`
- Se tu chuyen huong sang trang dang nhap.
- Tai khoan mac dinh: **username: `admin`** / **password: `admin123`**
- **Doi mat khau nay ngay khi co chuc nang doi mat khau (hoac tu sua truc tiep trong DB bang `password_hash()` neu can dung lau dai).**

### Buoc 5 — Cho phep may khac (VM chay Agent) truy cap
Mac dinh XAMPP chi lang nghe `localhost`. De VM Windows chay Agent goi duoc API:

1. Lay dia chi IP LAN cua may chay XAMPP: mo CMD, go `ipconfig`, lay dia chi dang `192.168.x.x`.
2. Mo **Windows Defender Firewall** tren may chay XAMPP → **Allow an app through firewall** →
   dam bao **Apache HTTP Server** (hoac cho phep port 80) duoc tick cho ca Private va Public network.
3. Tu may VM khac (cung mang LAN/mang ao), test truy cap:
   ```
   http://192.168.x.x/dlp_server/api/agent_policy.php?hostname=PC-KINHDOANH-01
   ```
   voi header `Authorization: Bearer test-token-kd-01` (dung Postman de test co header de hon trinh duyet).

## 3. Cau truc thu muc

```
dlp_server/
├── sql/schema.sql              -- Import file nay vao phpMyAdmin dau tien
├── config/database.php         -- Sua thong tin ket noi MySQL o day neu can
├── includes/                   -- Cac file dung chung (auth, helpers, layout)
├── api/                        -- 3 endpoint cho Agent goi (xem docs/API_CONTRACT.md)
├── admin/                      -- Toan bo giao dien quan tri (can dang nhap)
└── docs/API_CONTRACT.md        -- Gui file nay cho nguoi lam Agent
```

## 4. Du lieu mau da co san (dung de test ngay)

| Loai | Gia tri |
|---|---|
| Tai khoan admin | `admin` / `admin123` |
| Endpoint test 1 | hostname=`PC-KINHDOANH-01`, token=`test-token-kd-01`, nhom=Kinh doanh |
| Endpoint test 2 | hostname=`PC-IT-01`, token=`test-token-it-01`, nhom=IT |
| Content rules | PII_CCCD, PII_PHONE_VN, PII_EMAIL, FINANCE_CREDIT_CARD, INTERNAL_LABEL |
| Network blacklist | drive.google.com, dropbox.com, wetransfer.com, port 22 |

## 5. Cac trang chinh trong Admin UI

| Trang | Chuc nang |
|---|---|
| `dashboard.php` | Thong ke tong quan, vi pham gan nhat |
| `groups.php` | Tao/xoa nhom nguoi dung (tu dong tao 6 policy mac dinh khi tao nhom moi) |
| `policy.php` | Cau hinh ma tran Exit Point x State cho tung nhom, gan Content Rules |
| `content_rules.php` | Them/sua/tat regex hoac dictionary rule |
| `usb_whitelist.php` | Quan ly thiet bi USB duoc mien tru kiem soat |
| `network_blacklist.php` | Quan ly domain/IP/port bi chan |
| `endpoints.php` | Tao endpoint moi (sinh API token), xem trang thai online/offline |
| `violations.php` | Xem toan bo nhat ky vi pham, co bo loc |

## 6. Buoc tiep theo (chua lam trong ban nay)

- Trang doi mat khau admin.
- Xac thuc CSRF token cho cac form (hien tai chua co, nen them truoc khi coi la "production-ready" — neu hoi don hoi ve bao mat cua chinh Server, day la diem can nhac toi).
- Endpoint API cho Agent tu dang ky (hien tai dang dung cach thu cong: Admin tao endpoint truoc, dua token cho Agent).
- Job dinh ky (cron) de tu dong danh dau OFFLINE thay vi tinh toan moi lan load Dashboard/Endpoints (hien tai dang lam tam bang cach UPDATE ngay khi load trang, du dung nhung chua toi uu).
