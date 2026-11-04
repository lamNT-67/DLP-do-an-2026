# Clipboard + Screenshot Agent (`agent/clipboard_agent.py`)

Chặn 2 exit point `CLIPBOARD` (copy-paste) và `SCREEN_CAPTURE` (chụp màn hình). Hai kênh dùng chung một cơ chế: một cửa sổ ẩn đăng ký `AddClipboardFormatListener`, nên Windows báo `WM_CLIPBOARDUPDATE` cho agent **mỗi khi clipboard thay đổi**, không phải dò định kỳ.

## Luồng xử lý

| Nội dung clipboard | Exit point | Xử lý |
|---|---|---|
| Chữ (kể cả copy ô Excel, đoạn Word) | CLIPBOARD | `scan_text()` của Content Inspection Engine → đủ ngưỡng thì xoá |
| File copy trong Explorer (Ctrl+C) | CLIPBOARD | `inspect_file()` từng file (tối đa 20) → file nhạy cảm thì xoá |
| Chỉ có ảnh, không kèm chữ (PrtSc, Win+Shift+S) | SCREEN_CAPTURE | Xoá ảnh |

Khi chặn, agent **thay nội dung clipboard bằng một dòng thông báo** (paste ra sẽ thấy lý do bị chặn), ghi log JSON (dữ liệu nhạy cảm đã che) và gửi report về server với action `BLOCKED_DELETE`. Policy `REPORT_ONLY` chỉ ghi nhận, không xoá.

Copy ô Excel luôn kèm một tấm ảnh của vùng ô, nên agent chỉ coi là ảnh chụp màn hình khi clipboard **chỉ có ảnh, không có chữ**, hoặc khi chủ sở hữu clipboard là công cụ chụp màn hình.

Chặn chụp màn hình gồm 4 lớp, lớp sau là lưới dự phòng cho lớp trước:

| Lớp | Cách làm | Chặn được |
|---|---|---|
| 0. Phím bấm | Hook bàn phím mức thấp (`WH_KEYBOARD_LL`) nuốt phím trước khi Windows xử lý | PrtSc (mọi tổ hợp), Win+Shift+S, Win+Shift+R, Win+Alt+R. **Không có ảnh nào được tạo ra** |
| 1. Clipboard | Xoá ảnh vừa vào clipboard | Mở Snipping Tool bằng chuột rồi chụp |
| 2. Thư mục ảnh | Xoá file mới trong `Pictures\Screenshots` | Công cụ tự lưu ảnh ra file |
| 3. Tiến trình | Tắt `SnippingTool.exe`, `ScreenSketch.exe`, `ScreenClippingHost.exe` mỗi giây | Công cụ chụp màn hình của Windows đang mở |

Khi nuốt tổ hợp có phím Win, agent bấm giả một phím "trống" (mã 0xE8) để Windows không mở menu Start lúc thả phím Win. Gõ phím bình thường (s, S, Win+S) không bị ảnh hưởng. Policy `REPORT_ONLY` thì phím vẫn hoạt động, chỉ ghi nhận.

## Vì sao không chạy như Windows Service

Service chạy ở Session 0, không nhìn thấy clipboard và màn hình của người dùng. Agent này phải chạy trong phiên đăng nhập của user, khởi động bằng Task Scheduler "At logon" (cùng cách `notify.ps1` đang chạy). Nó dùng lại `api_token` trong `config.ini` do service chính đăng ký, không tự đăng ký để tránh 2 tiến trình cùng đăng ký một máy.

## Chạy thử

```
cd agent
python -m unittest dev_tools.test_clipboard_agent -v     # 27 test phần logic
python clipboard_agent.py --demo                          # chặn thật, không cần server
python clipboard_agent.py --demo --monitor                # chỉ ghi nhận
```

Ở chế độ `--demo`, ảnh chụp màn hình **mới** trong `Pictures\Screenshots` sẽ bị xoá và Snipping Tool bị tắt cho tới khi bấm Ctrl+C. Ảnh cũ không bị đụng tới.

## Kịch bản test tay

| # | Thao tác | Kết quả mong đợi |
|---|---|---|
| 1 | Notepad: gõ `Số CCCD: 001203012345`, bôi đen, Ctrl+C, rồi Ctrl+V | Dán ra dòng `[DLP] Nội dung đã bị chặn...` |
| 2 | Copy `hẹn 3h chiều nhé` rồi dán | Dán bình thường |
| 3 | Copy một email lẻ rồi dán | Dán bình thường, log ghi `LOGGED` |
| 4 | Mở file mẫu xlsx khách hàng, copy cột CCCD, dán vào Notepad | Bị chặn |
| 5 | Trong Excel, copy ô tiêu đề `Họ tên`, dán | Dán bình thường (không bị nhầm là ảnh chụp) |
| 6 | Bấm PrtSc | Không có gì xảy ra; cửa sổ agent in `CHAN phim PrtSc` |
| 7 | Bấm Win+Shift+S | Màn hình chụp không hiện ra, menu Start không bật lên |
| 8 | Bấm Win+PrtSc | Không có file mới trong `Pictures\Screenshots` |
| 8b | Mở Snipping Tool bằng chuột từ menu Start | Bị tắt trong khoảng 1 giây (lớp 3) |
| 8c | Gõ chữ thường có chữ s, Win+S để tìm kiếm | Hoạt động bình thường |
| 9 | Explorer: chọn file xlsx khách hàng, Ctrl+C, sang Desktop Ctrl+V | Không dán được file |

Log nằm ở `agent\logs\dlp_events.log` (hoặc thư mục trong biến môi trường `DLP_LOG_DIR`).

## Giới hạn (ghi trung thực trong báo cáo)

Hook bàn phím chỉ hoạt động khi agent đang chạy trong phiên của người dùng, và không áp dụng ở màn hình đăng nhập/khoá máy của Windows. Không chặn được chụp màn hình bằng điện thoại, hay phần mềm chụp/quay màn hình lưu thẳng ra file ở thư mục khác (OBS, ShareX…), trừ khi thêm tiến trình đó vào danh sách tắt. Ảnh chụp không được quét nội dung (chưa có OCR), nên policy BLOCK chặn mọi ảnh chụp chứ không phân biệt ảnh có CCCD hay không. Kéo-thả file (drag and drop) không đi qua clipboard nên không bị kênh này chặn; chép file ra USB do agent USB xử lý. Agent xoá clipboard *sau khi* copy nhưng *trước khi* paste; trong khoảng vài mili giây đó dữ liệu vẫn nằm trong bộ nhớ. Người có quyền admin có thể tắt agent. Đây là giới hạn chung của giải pháp user-mode.
