 1. Yêu cầu trước khi cài đặt

Trước khi cài đặt, cần chuẩn bị:

- Máy tính chạy Windows.
- Python 3.10 trở lên, khi cài đặt nhớ tích chọn **Add python.exe to PATH**.
- Mở PowerShell bằng quyền Administrator.
- Máy chủ DLP đã chạy trên XAMPP. Máy cài Agent không cần cài XAMPP.

2. Lấy Enrollment Key

Trên máy chủ DLP, mở trình duyệt và truy cập:

`http://IP-MAY-XAMPP/dlp_server/admin/settings.php`



Trong mục Settings, sao chép **Enrollment Key** để sử dụng ở bước cài đặt. 

3. Cài đặt DLP Agent

Mở PowerShell bằng quyền Administrator, sau đó chạy lần lượt các lệnh sau để tải mã nguồn về máy:

```powershell
git clone https://github.com/lamNT-67/DLP-do-an-2026.git
cd DLP-do-an-2026\agent\service
```

Sau khi vào thư mục `service`, nhấp đúp vào file `install.bat`. Khi Windows hỏi quyền quản trị, chọn **Yes** để tiếp tục.

Bộ cài sẽ yêu cầu nhập các thông tin sau:

- Server URL:** Địa chỉ API của máy chủ DLP
- Hostname:** Tên máy tính cần cài Agent. Có thể nhấn Enter để sử dụng tên máy mặc định.
- Enrollment Key:** Khóa đã lấy ở bước 2.

Sau khi nhập đủ thông tin, chờ bộ cài chạy xong. Chương trình sẽ tự động sao chép các file cần thiết vào `C:\DLP`, cài những thư viện Python còn thiếu và tạo hai Windows Service để Agent chạy nền.

Hai service được cài đặt là:

- `DLPNetworkAgent`: Theo dõi hoạt động mạng theo cấu hình của hệ thống DLP.
- `DLPSftpScpAgent`: Theo dõi hoạt động liên quan đến SFTP/SCP.

Trong lần chạy đầu tiên, Agent sẽ đăng ký với máy chủ và lưu token vào file cấu hình `C:\DLP\agent\config.ini`. Không cần tự nhập token nếu quá trình đăng ký thành công.

4. Kiểm tra sau khi cài đặt

Sau khi cài xong, vẫn trong PowerShell với quyền Administrator, chạy lệnh:

```powershell
Get-Service DLP*
```

Nếu cả `DLPNetworkAgent` và `DLPSftpScpAgent` đều có trạng thái `Running` thì các service đang hoạt động.



Cuối cùng, đăng nhập trang quản trị DLP, vào mục Device để kiểm tra máy tính vừa cài đặt. Nếu máy hiển thị trạng thái **ONLINE** thì có thể xem như đã kết nối thành công.

