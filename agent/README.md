Windows, mở PowerShell bằng quyền Administrator 
Python 3.10+, chạy pip install psutil requests
Server đã chạy sẵn qua XAMPP
Setup lần đầu

Vào trang Admin, mục Settings, lấy 1 Enrollment Key. Rồi copy config.ini.example thành config.ini, sửa lại:

ini
[agent]
hostname = TEN-MAY
api_token =
enrollment_key = KEY-VUA-LAY
server_url = http://<ip-may-xampp>/dlp_server/api

Cứ để api_token trống, chạy lần đầu nó tự đăng ký rồi tự ghi token vào file này luôn, không cần động vào nữa. Lưu ý nếu hostname này đăng ký rồi (báo lỗi 409) thì vào Admin > Devices xoá cái cũ đi trước khi chạy lại.

Chạy
powershell
python network_agent.py

Mở thêm 1 cửa sổ Admin khác chạy song song:

powershell
python sftp_scp_agent.py

Thấy dòng "Bat dau giam sat..." là ổn, có "Heartbeat OK" 
