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

Khi nhiều policy áp dụng cho cùng một exit point, Agent đánh giá lần lượt từng
policy với action, phạm vi loại file, content rules và ngoại lệ của policy đó.
Policy có ngoại lệ trùng khớp sẽ cho qua phần kiểm tra của chính nó. Agent chọn
kết quả theo thứ tự `BLOCK > LOG > ALLOW` và dùng ID, action, rule và bằng chứng
của policy được chọn để lập báo cáo. Nếu cùng kết quả, thứ tự ID dạng chuỗi
quyết định policy được chọn. Kết quả ngoài phạm vi có ưu tiên thấp nhất.

Browser và SCP/SFTP/FTP lọc theo đuôi file trong phạm vi từng policy.
Với file trên CLIPBOARD và USB, danh sách loại file dùng cho kiểm soát loại file;
content rules vẫn áp dụng với mọi đuôi file dù có thêm policy khác.
Danh sách luôn chặn của từng policy cũng áp dụng theo loại thật khi đuôi file
nằm ngoài phạm vi. Nếu không đọc được file để xác minh loại thật, áp dụng
`UNREADABLE` theo action của policy.
CLIPBOARD dạng văn bản và NETWORK_WEB dạng kết nối không có điều kiện loại file.

| Bước | Xử lý | Kết quả nếu dừng tại bước này |
|---|---|---|
| 1 | Kênh không có policy | `ALLOW / NOT_GOVERNED` |
| 2 | Ngoại lệ `allowed_files` / `allowed_locations` | `ALLOW / ALLOWED_FILE`, `ALLOWED_LOCATION` |
| 3 | Đọc file (thử lại 3 lần nếu file đang bị khoá); tính SHA-256 | Không đọc được: `UNREADABLE` (fail-closed) |
| 4 | Nhận diện loại file thật bằng magic number | Ghi nhận `extension_mismatch` nếu bị đổi đuôi |
| 5 | File Type Control: đuôi khai báo hoặc loại thật nằm trong danh sách luôn chặn | `FILE_TYPE_BLOCKED` |
| 6 | Policy không có content rule | `BLOCK` → `EXIT_POINT_BLOCKED`; `REPORT_ONLY` → `EXIT_POINT_MONITORED` |
| 7 | Trích xuất text; zip được quét 1 cấp bên trong | Zip chứa file bị cấm: `FILE_TYPE_BLOCKED`; có mật khẩu: `ENCRYPTED_CONTENT` |
| 8 | Quét nội dung 2 tầng + chấm điểm | `CONTENT_MATCH`, `CLEAN` hoặc `INSPECTION_INCOMPLETE` |

Ánh xạ sang 4 trạng thái trong báo cáo: không có policy = **OPEN**; `REPORT_ONLY` = **MONITORED**; `BLOCK` có content rule = **CONTROLLED**; `BLOCK` không có content rule = **BLOCKED**.

### Đọc inspection metadata

`inspect_file()` trả về `inspection_coverage` cho **policy được chọn**. Dùng `verdict` để thực thi và `inspection_coverage` để biết engine đã kiểm tra được bao nhiêu.

| `inspection_coverage` | Ý nghĩa |
|---|---|
| `FULL` | Engine đã đọc đủ số byte theo kích thước file tại thời điểm bắt đầu đọc, trích xuất phần văn bản mà bộ đọc hỗ trợ và quét xong với bộ rule. File text rỗng có thể đạt `FULL`. |
| `PARTIAL` | Đã chạm giới hạn đọc, trích xuất hoặc quét, phải dùng bộ trích xuất chuỗi best-effort, hoặc policy đã quyết định trước khi quét. Ví dụ khác gồm ZIP có thành viên bị bỏ qua và PDF có trang không trả về text. |
| `UNSUPPORTED` | Engine không thể trích xuất văn bản của file, chẳng hạn ảnh cần OCR, PDF thiếu thư viện đọc, PDF chỉ có trang không trả về text, hoặc file mã hoá cần mật khẩu. |
| `ERROR` | Đọc file gặp lỗi, bộ trích xuất báo lỗi parse, hoặc một rule không biên dịch được khi quét. Dictionary có 0 từ khóa thực thi cũng ghi `scan=ERROR`. |

`inspection_stages` ghi riêng ba bước `read`, `extract`, `scan`. Mỗi bước đánh giá phần đầu vào mà bước đó nhận được. Giá trị `NOT_RUN` chỉ xuất hiện ở từng bước. Ví dụ, một file đã đọc đủ nhưng phần text trích xuất vượt giới hạn ký tự có thể trả về kết quả sau.

```json
{
  "verdict": "ALLOW",
  "reason": "INSPECTION_INCOMPLETE",
  "inspection_coverage": "PARTIAL",
  "inspection_stages": {"read": "FULL", "extract": "FULL", "scan": "PARTIAL"},
  "inspected": true
}
```

Trạng thái tổng hợp ưu tiên `ERROR`, sau đó đến `UNSUPPORTED`. Chỉ khi cả ba bước đều `FULL` thì kết quả file mới là `FULL`. Với ngoại lệ policy, `reason` vẫn là `ALLOWED_FILE` hoặc `ALLOWED_LOCATION`, các bước chưa chạy ghi `NOT_RUN`. Bước đọc đo lượng byte cấp cho bộ trích xuất, độc lập với việc tính SHA-256. `FULL` mô tả khả năng của bộ đọc đã chọn, ví dụ phần văn bản của PDF và các phần XML nêu ở mục 4. Engine chưa thực hiện OCR hay xác nhận file ổn định trong suốt quá trình đọc.

Khi quét và không có match, engine trả về `CLEAN` chỉ với `FULL`, các trường hợp còn lại trả về `INSPECTION_INCOMPLETE`. Nếu bộ trích xuất không trả về text, đường xử lý `NOT_INSPECTABLE` vẫn áp dụng. Một match trong lần quét chưa hoàn tất vẫn có thể cho `CONTENT_MATCH` và verdict `LOG` hoặc `BLOCK`. Cờ `inspected` cho biết engine đã gọi bộ quét text, kể cả khi phần text nhận được rỗng.

`scan_text()` và `scan_content_with_rules()` trả về `inspection_coverage` cho riêng bước quét. Khi đạt giới hạn số match, bộ quét dừng tìm và ghi `PARTIAL`. Log JSON qua `to_log_inspection()` mang theo metadata hiện có. Worker cURL chuyển trạng thái tổng hợp vào journal và dùng trường `inspection_limit` cho các lần quét bị giới hạn. Payload của `to_report_fields()` tiếp tục dùng các trường báo cáo hiện có.

Lỗi biên dịch của một rule (kể cả `OverflowError`) chỉ ảnh hưởng coverage của policy chứa rule đó. Các rule hợp lệ tiếp tục quét. Engine giữ match tìm được và chọn verdict theo thứ tự `BLOCK > LOG > ALLOW`. Kết quả ghi coverage của policy thắng.

Với XLSX, engine đọc bảng shared strings khi gặp ô dùng chỉ mục. Nếu chỉ mục không phân giải được, engine ghi `XLSX_SHARED_STRING_SKIPPED` và `extract=PARTIAL` khi còn văn bản để quét. Nếu toàn bộ phần văn bản bị mất, engine ghi `XLSX_SHARED_STRING_ERROR` và `extract=ERROR`. Workbook dùng inline strings có thể đạt `FULL` khi thiếu bảng shared strings.

Với ZIP, thiếu codec cho file cần đọc cho kết quả `UNSUPPORTED` với note `ZIP_CODEC_UNAVAILABLE`. Tính năng ZIP mà thư viện chưa hỗ trợ ghi `ZIP_FEATURE_UNSUPPORTED`. Lỗi cấu trúc, dữ liệu nén hỏng hoặc checksum sai cho kết quả `ERROR` với note `ZIP_CORRUPT`.

Khi worker cURL cũ gửi `CLEAN` mà thiếu `inspection_coverage`, phía nhận dùng reason `INSPECTION_INCOMPLETE` và để trống bằng chứng coverage. Verdict, policy và trường `inspection_limit` (nếu có) của worker tiếp tục quyết định cách xử lý và ghi journal.

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

Các test dùng fixture tổng hợp để kiểm tra verdict, giới hạn từng bước, trạng thái của PDF và archive, rule lỗi, định dạng log và tốc độ quét. Để chạy cả các consumer và giao thức worker cURL, dùng `python -m unittest discover -s dev_tools -p "test_*.py" -v` trong thư mục `agent`. Các test dùng API Win32 cần chạy trên Windows.
