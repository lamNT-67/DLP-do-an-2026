DLP Agent

Agent Windows của hệ thống DLP trong đồ án, viết bằng Python. Agent lấy policy từ máy chủ DLP, kiểm soát các kênh dữ liệu ra khỏi máy và gửi log về máy chủ.
1. Yêu cầu trước khi cài đặt

Trước khi cài đặt, cần chuẩn bị:

- Máy tính chạy Windows.
- Python 3.10 trở lên, khi cài đặt nhớ tích chọn **Add python.exe to PATH**.
- Mở PowerShell bằng quyền Administrator.
- Máy chủ DLP đã chạy trên XAMPP. Máy cài Agent không cần cài XAMPP.
- Máy cài Agent có kết nối mạng trong lúc cài (tải thư viện Python và công cụ NSSM).

2. Lấy Enrollment Key

Trên máy chủ DLP, mở trình duyệt và truy cập:

http://IP-MAY-XAMPP/dlp_server/admin/settings.php

Trong mục Settings, sao chép **Enrollment Key** để sử dụng ở bước cài đặt.

## 3. Cài đặt DLP Agent

Mở PowerShell bằng quyền Administrator, sau đó chạy lần lượt các lệnh sau để tải mã nguồn về máy:

powershell
git clone https://github.com/lamNT-67/DLP-do-an-2026.git
cd DLP-do-an-2026\agent\service


Sau khi vào thư mục `service`, nhấp đúp vào file `install.bat`. Khi Windows hỏi quyền quản trị, chọn **Yes** để tiếp tục.

Bộ cài sẽ yêu cầu nhập các thông tin sau:

- Server URL:Địa chỉ API của máy chủ DLP.
- Hostname:Tên máy tính cần cài Agent. Có thể nhấn Enter để sử dụng tên máy mặc định.
- Enrollment Key:Khóa đã lấy ở bước 2.

Sau khi nhập đủ thông tin, chờ bộ cài chạy xong. Chương trình sẽ tự động sao chép các file cần thiết vào `C:\DLP`, cài những thư viện Python còn thiếu, Service và  tác vụ (Scheduled Task)** để Agent chạy nền.

Ba service được cài đặt là:

- DLPNetworkAgent: Theo dõi hoạt động mạng web theo cấu hình của hệ thống DLP.
- DLPSftpScpAgent: Theo dõi hoạt động SCP/SFTP/FTP.
- DLPBrowserAgent: Nhận file từ extension trình duyệt (qua `127.0.0.1:18765`) để kiểm tra nội dung trước khi upload.

Hai tác vụ chạy khi người dùng đăng nhập là:

- DLPClipboardAgent: Chặn sao chép dữ liệu nhạy cảm (clipboard) và chụp màn hình. Chạy trong phiên của người dùng vì service không nhìn thấy clipboard và màn hình.
- DLPNotifier: Hiện thông báo trên máy khi một thao tác bị chặn.

Ngoài ra bộ cài còn:

- Cấp cho nhóm Users quyền ghi vào thư mục log C:\ProgramData\DLP\logs để agent clipboard ghi được log.
- Đặt chính sách của Edge WebCaptureEnabled=0 để tắt công cụ Screenshot riêng của Edge. Chính sách này áp dụng cho cả máy.

Trong lần chạy đầu tiên, Agent sẽ đăng ký với máy chủ và lưu token vào file cấu hình C:\DLP\agent\config.ini. Không cần tự nhập token nếu quá trình đăng ký thành công. Nếu cài lại, bộ cài giữ nguyên config.ini hiện có.

4. Bật extension trình duyệt (Edge / Chrome)

Extension **không tự bật** sau khi cài, vì trình duyệt không cho cài extension ngầm trên máy không thuộc domain. Sau khi cài xong, làm một lần trong Edge:

1. Mở edge://extensions và bật Chế độ nhà phát triển.
2. Bấm Tải tiện ích đã giải nén.
3. Chọn thư mục C:\DLP\agent\browser_extension.

Lưu ý:

- Extension kiểm tra mỗi file tối đa 2 MiB; file lớn hơn bị chặn.

### Curl Agent V1

Chạy `python -B agent/curl_agent.py --config C:\DLP\agent\config.ini` từ thư mục gốc của repo, trong phiên Windows đang thử nghiệm. Chọn exit point `CLIENT_CURL` trong policy của thiết bị đã đăng ký. Agent tự phát hiện các tiến trình `curl.exe` khi người dùng gọi curl như bình thường. Cơ chế dò tiến trình có thể phát hiện sau khi dữ liệu đã đến đích. [Cách chạy và kiểm thử Curl Agent](docs/CURL_AGENT.md)

5. Các chức năng của Agent

 Chặn truy cập web: Luật tường lửa Windows chặn domain/IP 
 SCP / SFTP / FTP  Quét file rồi dừng tiến trình; hoặc chặn cổng 22/21/990 nếu chặn cả kênh 
Upload qua trình duyệt Extension gửi file cho agent quét, chặn nếu vi phạm 
Clipboard  Xóa nội dung clipboard chứa dữ liệu nhạy cảm 
Chụp màn hình  Chặn phím PrtSc, Win+Shift+S; tắt Snipping Tool; tắt Screenshot của Edge

Cách policy BLOCK quyết định phạm vi chặn:

- Không chọn loại file và không gán luật nội dung: chặn cả kênh.
- Chỉ chọn loại file: chặn các loại file đó.
- Chỉ gán luật nội dung: quét mọi file.
- Chọn cả hai: chỉ quét các loại file đã chọn.
- Policy REPORT_ONLY chỉ ghi nhận, không chặn.

Agent làm mới policy mỗi 60 giây. 

6. Hạn chế đã biết

- SFTP/FTP gõ lệnh trong phiên hoặc dùng giao diện (WinSCP, FileZilla): tên file không nằm trên dòng lệnh nên agent không biết trước. Đã đo: `put` file 1 KB, 50 KB, 500 KB, 2 MB **lọt hoàn toàn**; file 32 MB bị dừng giữa chừng nhưng khoảng 200 KB đầu đã sang máy đích. Giảm chu kỳ quét từ 0,25 xuống 0,05 giây không thay đổi kết quả. Muốn chắc chắn thì chặn cả kênh.
- File lệnh (`sftp -b`, `ftp -s:`): một file vi phạm làm cả phiên bị dừng, kể cả các file sạch đi cùng.
- Cổng 22 dùng chung** cho SCP, SFTP và SSH: chặn cả kênh là chặn cả ba. Tiến trình được nhận diện theo tên.
- Trình duyệt: extension ở chế độ nhà phát triển có thể bị người dùng tắt; file trên 2 MiB bị chặn dù sạch; upload tạo bằng Blob/script chưa được quét; code trong trang không phải ranh giới bảo mật.
- Chụp màn hình: ảnh chụp không được quét nội dung (chưa có OCR) nên policy BLOCK chặn mọi ảnh; không chặn OBS, ShareX hay chụp bằng điện thoại.
- Clipboard: dữ liệu còn trong bộ nhớ vài mili giây trước khi bị xóa; kéo thả file không đi qua clipboard.
- Quyền ghi log: nhóm `Users` có quyền ghi vào thư mục log nên người dùng thường có thể sửa log cục bộ (máy chủ vẫn giữ bản đã gửi).
- Quản trị viên máy luôn có thể tắt agent. Đây là giới hạn chung của giải pháp chạy ở user-mode.


7. Gỡ cài đặt

Mở PowerShell bằng quyền Administrator, vào thư mục `agent\service` và nhấp đúp `uninstall.bat` (hoặc chạy `.\uninstall.bat`). Script dừng service, xóa tác vụ, xóa luật tường lửa `DLP_*` và xóa giá trị `WebCaptureEnabled` của Edge. Tham số `-RemoveFiles` của `uninstall.ps1` còn xóa `C:\DLP` và `C:\ProgramData\DLP`, nên hãy sao lưu `config.ini` trước.
