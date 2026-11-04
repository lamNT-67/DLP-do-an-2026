# Content Inspection Engine (`agent/content_inspection.py`)

Module dùng chung cho mọi exit point. Trả lời câu hỏi: **file/nội dung này có được phép rời khỏi máy không?** Không phụ thuộc thư viện ngoài, trừ `pypdf` (để đọc PDF).

## 1. Cách gọi từ các agent khác

```python
from policy_utils import get_exit_point_status
from content_inspection import inspect_file, scan_text, to_log_inspection, to_report_fields

status = get_exit_point_status(policy["applicable_policies"], "USB")   # hoặc NETWORK_SCP_SFTP...
res = inspect_file(path, status, destination="E:\\")                  # với file
# res = scan_text(clipboard_text, status["content_rules"])             # với clipboard

if res["verdict"] == "BLOCK":   action = "BLOCKED_DELETE"   # USB; SCP/SFTP: BLOCKED_KILL
elif res["verdict"] == "LOG":   action = "LOGGED"
else:                           action = None               # ALLOW: không cần báo cáo

payload.update(to_report_fields(res))                 # file_hash_sha256, matched_rule_ids, confidence_score
write_log_event(..., content_inspection=to_log_inspection(res), ...)
```

Hàm cũ `scan_content_with_rules(text, rules)` vẫn giữ nguyên tên và các khoá trả về, nên `network_agent.py` không phải sửa logic.

Chạy thử bằng dòng lệnh: `python content_inspection.py <file1> <file2> ...` (thêm `--full` để xem toàn bộ kết quả JSON).

## 2. Pipeline xử lý một file

| Bước | Xử lý | Kết quả nếu dừng tại bước này |
|---|---|---|
| 1 | Kênh không có policy | `ALLOW / NOT_GOVERNED` |
| 2 | Ngoại lệ `allowed_files` / `allowed_locations` | `ALLOW / ALLOWED_FILE`, `ALLOWED_LOCATION` |
| 3 | Đọc file (thử lại 3 lần nếu file đang bị khoá); tính SHA-256 | Không đọc được: `UNREADABLE` (fail-closed) |
| 4 | Nhận diện loại file thật bằng magic number | Ghi nhận `extension_mismatch` nếu bị đổi đuôi |
| 5 | File Type Control: đuôi khai báo hoặc loại thật nằm trong danh sách luôn chặn | `FILE_TYPE_BLOCKED` |
| 6 | Policy không có content rule | `BLOCK` → `EXIT_POINT_BLOCKED`; `REPORT_ONLY` → `EXIT_POINT_MONITORED` |
| 7 | Trích xuất text; zip được quét 1 cấp bên trong | Zip chứa file bị cấm: `FILE_TYPE_BLOCKED`; có mật khẩu: `ENCRYPTED_CONTENT` |
| 8 | Quét nội dung 2 tầng + chấm điểm | `CONTENT_MATCH` hoặc `CLEAN` |

Ánh xạ sang 4 trạng thái trong báo cáo: không có policy = **OPEN**; `REPORT_ONLY` = **MONITORED**; `BLOCK` có content rule = **CONTROLLED**; `BLOCK` không có content rule = **BLOCKED**.

## 3. Nhận diện loại file thật (chống đổi đuôi)

Đọc các byte đầu file thay vì tin vào phần mở rộng: `%PDF` → pdf, `MZ` → exe, `PK..` → mở zip xem có `word/document.xml` (docx), `xl/workbook.xml` (xlsx), `ppt/presentation.xml` (pptx) hay là zip thường; `D0 CF 11 E0` → Office 97-2003 hoặc Office 2007+ đã đặt mật khẩu (chứa `EncryptedPackage`); cùng với RAR, 7z, gzip, SQLite, PNG, JPEG, GIF. File text có từ 2 dòng `CREATE TABLE` / `INSERT INTO` trở lên được coi là dump SQL dù mang đuôi `.txt`.

## 4. Trích xuất nội dung

| Loại | Cách đọc |
|---|---|
| txt, csv, sql, json... | Tự nhận UTF-8 / UTF-16 (có hoặc không BOM) / Windows-1258 |
| docx, pptx | Đọc XML bên trong (thân văn bản, header, footer, chú thích, ghi chú slide) |
| xlsx | Ghép sharedStrings với từng ô; mỗi hàng một dòng, các ô cách nhau bằng tab |
| pdf | `pypdf`; PDF chỉ có owner-password vẫn đọc được |
| doc, xls, ppt cũ; sqlite; file nhị phân lạ | Best-effort: trích chuỗi ASCII và UTF-16 (giống lệnh `strings`) |
| zip | Quét tối đa 50 file con, 1 cấp; chặn zip bomb (file con > 20 MB hoặc tỉ lệ nén > 200) |

## 5. Quét nội dung 2 tầng

Tầng 1, regex/dictionary (lấy từ server), tìm ứng viên. Tầng 2, validator xác nhận ứng viên là dữ liệu thật, giúp giảm false positive:

| Rule | Validator |
|---|---|
| `PII_CCCD` | 12 số, 3 số đầu là mã tỉnh hợp lệ (001–096), số thứ 4 là mã giới tính/thế kỷ (0–3) |
| `FINANCE_CREDIT_CARD` | 13–19 số, qua thuật toán Luhn |
| `PII_PHONE_VN` | 10 số (hoặc +84), đầu số di động thật của các nhà mạng |
| `INTERNAL_LABEL` (dictionary) | Từ đơn: khớp có dấu ("Mật" không khớp "mắt", "mất", "format"). Cụm ≥ 2 từ: khớp cả khi gõ không dấu ("tuyet mat") |

Validator được chọn theo tên rule (chứa `CCCD`, `CARD`, `PHONE`, `EMAIL`), nên admin có thể sửa regex trên web mà vẫn giữ được bước xác nhận.

## 6. Chấm điểm tin cậy (Confidence Scoring)

Mức gốc của mỗi rule bằng `severity` cấu hình trên server, sau đó điều chỉnh. Mọi điều chỉnh đều được ghi lại trong `reasons` để giải thích kết quả.

| Điều kiện | Điều chỉnh | Lý do |
|---|---|---|
| ≥ 10 giá trị **khác nhau** của cùng rule | +1 | Dữ liệu hàng loạt, nghi cố ý tuồn dữ liệu |
| Chỉ 1 giá trị, không có từ khoá ngữ cảnh gần đó (VD: "CCCD", "số thẻ") | −1 | Có thể chỉ là con số trùng hợp |
| Khớp ≥ 2 nhóm dữ liệu (VD: PII + FINANCE) | +1 | Hồ sơ khách hàng hoàn chỉnh |
| File bị đổi đuôi so với loại thật | +1 | Dấu hiệu cố tình che giấu |

Với policy `BLOCK`, file chỉ bị chặn khi mức cuối ≥ `BLOCK_MIN_LEVEL` (mặc định `MEDIUM`); dưới ngưỡng thì chỉ ghi log. Nhờ vậy một email lẻ trong file (mức `LOW`) không làm gián đoạn công việc.

## 7. Log không làm lộ dữ liệu

Giá trị nhạy cảm được che trước khi ghi log: `001203012345` → `001*******45`, `nguyenvana@abc.vn` → `n***@abc.vn`. Log chỉ giữ tối đa 3 mẫu đã che cho mỗi rule, cùng với SHA-256 của file để phục vụ điều tra.

## 8. Cấu hình (đầu file `content_inspection.py`)

`MAX_FILE_BYTES` (50 MB), `MAX_TEXT_READ_BYTES` (5 MB), `BULK_THRESHOLD` (10), `BLOCK_MIN_LEVEL` (`MEDIUM`), `BLOCK_ENCRYPTED` (`True`), `BLOCK_TOO_LARGE` (`False`).

## 9. Giới hạn đã biết (ghi trung thực trong báo cáo)

Ảnh và PDF scan không có lớp text thì chưa quét được (cần OCR; hướng phát triển). RAR/7z chưa mở được nội dung (nên để trong danh sách luôn chặn). File Office/PDF lớn hơn 50 MB không quét nội dung, mặc định chỉ ghi log. Doc/xls cũ chỉ quét best-effort. Số CCCD lưu trong Excel dưới dạng *số* sẽ mất số 0 ở đầu nên không khớp regex (thực tế CCCD thường được lưu dạng text). Regex + validator vẫn có thể bỏ sót dữ liệu bị cố tình biến đổi (chèn ký tự, viết bằng chữ); đây là giới hạn chung của phương pháp rule-based so với ML (tham khảo [7], [12]).

## 10. Kiểm thử

```
cd agent
python -m unittest dev_tools.test_content_inspection -v
python dev_tools/make_samples.py          # tạo 12 file mẫu trong dev_tools/dlp_samples/
python content_inspection.py dev_tools/dlp_samples
```

Bộ test gồm 35 ca: validator, false positive, chấm điểm, đổi đuôi file, zip chứa file cấm, zip có mật khẩu, UTF-16, ngoại lệ, fail-closed, log đã che dữ liệu, PDF, và hiệu năng (file 5 MB dày đặc dữ liệu nhạy cảm quét dưới 1 giây).
