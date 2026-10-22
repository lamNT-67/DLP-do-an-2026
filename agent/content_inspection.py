"""
Content Inspection Engine - DLP Agent
=====================================
Module dùng chung cho mọi exit point (SCP/SFTP/FTP, USB, Clipboard...).
Trả lời câu hỏi: "File/nội dung này có được phép rời khỏi máy không?"

Luồng xử lý của inspect_file():
    1. Ngoại lệ (allowed_files / allowed_locations)            -> ALLOW
    2. Nhận diện loại file THẬT bằng magic number               (chống đổi đuôi file)
    3. File Type Control: loại file luôn bị chặn (.sql, .exe...) -> chặn, không cần quét
       (kiểm tra cả đuôi khai báo, loại thật, và file nằm trong .zip)
    4. Exit point bị chặn hoàn toàn (policy BLOCK, không có content rule) -> chặn
    5. File mã hoá / không đọc được nội dung                    -> xử lý theo cấu hình
    6. Trích xuất text: txt/csv/sql, docx, xlsx, pptx, pdf, doc/xls cũ, zip
    7. Content Inspection 2 tầng: regex tìm ứng viên -> validator xác nhận
       (Luhn cho số thẻ, mã tỉnh cho CCCD, đầu số nhà mạng cho SĐT)
    8. Confidence Scoring: severity x số lượng x ngữ cảnh x kết hợp loại dữ liệu
    9. Ra quyết định: ALLOW / LOG / BLOCK

Không phụ thuộc thư viện ngoài, trừ pypdf (tuỳ chọn, để đọc PDF).
Chạy thử nhanh:  python content_inspection.py <file1> [file2 ...]
"""

import codecs
import hashlib
import html
import io
import json
import os
import re
import sys
import time
import unicodedata
import zipfile
from functools import lru_cache

# ============================================================================
# 1. CẤU HÌNH
# ============================================================================
LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
_LEVEL_IDX = {name: i for i, name in enumerate(LEVELS)}

MAX_FILE_BYTES = 50 * 1024 * 1024        # file lớn hơn: text chỉ quét phần đầu, office/pdf bỏ qua
MAX_TEXT_READ_BYTES = 5 * 1024 * 1024    # text thuần: đọc tối đa 5 MB đầu
MAX_TEXT_CHARS = 2_000_000               # tổng số ký tự đưa vào regex
MAX_HASH_BYTES = 500 * 1024 * 1024       # file lớn hơn: không tính SHA-256 (tránh treo máy)
MAX_ZIP_MEMBER_BYTES = 20 * 1024 * 1024  # mỗi file con trong zip/docx/xlsx
MAX_ZIP_RATIO = 200                      # tỉ lệ nén bất thường -> nghi zip bomb
MAX_ARCHIVE_MEMBERS = 50
MAX_PDF_PAGES = 200
MAX_MATCHES_PER_RULE = 500
SAMPLES_PER_RULE = 3

BULK_THRESHOLD = 10       # >= 10 giá trị KHÁC NHAU -> dữ liệu hàng loạt -> tăng 1 mức
CONTEXT_WINDOW = 60       # số ký tự phía trước match để tìm từ khoá ngữ cảnh
BLOCK_MIN_LEVEL = "MEDIUM"  # chỉ chặn khi confidence >= mức này (1 email lẻ = LOW -> chỉ log)
BLOCK_ENCRYPTED = True    # file mã hoá/đặt mật khẩu: không đọc được -> coi là rủi ro cao
BLOCK_TOO_LARGE = False   # office/pdf quá lớn không quét được: mặc định chỉ log

TEXT_EXTS = {"txt", "csv", "tsv", "sql", "json", "xml", "log", "md", "html", "htm",
             "ini", "cfg", "conf", "yaml", "yml", "py", "js", "ps1", "bat", "sh", "eml"}
EXECUTABLE_EXTS = {"exe", "dll", "sys", "scr", "com", "msi", "cpl"}
# Đuôi file hợp lệ nhưng khác tên với loại thật (không coi là "đổi đuôi")
_EXT_ALIASES = {"jpeg": "jpg", "xlsm": "xlsx", "xltx": "xlsx", "xltm": "xlsx", "docm": "docx",
                "dotx": "docx", "dotm": "docx", "pptm": "pptx", "potx": "pptx", "ppsx": "pptx",
                "jar": "zip", "apk": "zip", "odt": "zip", "ods": "zip", "odp": "zip", "epub": "zip",
                "db": "sqlite", "sqlite3": "sqlite", "tgz": "gz"}

_CATEGORY = {
    "pdf": "DOCUMENT", "docx": "DOCUMENT", "xlsx": "DOCUMENT", "pptx": "DOCUMENT",
    "doc": "DOCUMENT", "xls": "DOCUMENT", "ppt": "DOCUMENT", "txt": "DOCUMENT",
    "csv": "DOCUMENT", "office_encrypted": "DOCUMENT",
    "zip": "ARCHIVE", "rar": "ARCHIVE", "7z": "ARCHIVE", "gz": "ARCHIVE",
    "exe": "EXECUTABLE", "dll": "EXECUTABLE", "sys": "EXECUTABLE", "msi": "EXECUTABLE",
    "png": "IMAGE", "jpg": "IMAGE", "gif": "IMAGE", "bmp": "IMAGE",
}

# Mã tỉnh/thành trên CCCD (3 số đầu) theo Thông tư 07/2016/TT-BCA
VN_PROVINCE_CODES = {
    "001", "002", "004", "006", "008", "010", "011", "012", "014", "015", "017", "019",
    "020", "022", "024", "025", "026", "027", "030", "031", "033", "034", "035", "036",
    "037", "038", "040", "042", "044", "045", "046", "048", "049", "051", "052", "054",
    "056", "058", "060", "062", "064", "066", "067", "068", "070", "072", "074", "075",
    "077", "079", "080", "082", "083", "084", "086", "087", "089", "091", "092", "093",
    "094", "095", "096",
}
# Đầu số di động VN (sau số 0)
_VN_MOBILE_PREFIX = re.compile(r"^0(?:3[2-9]|5[25689]|7[06-9]|8[1-9]|9\d)")

# Bộ rule mặc định: dùng khi chạy CLI/test. Khi chạy thật, rule lấy từ server.
DEFAULT_RULES = [
    {"id": 1, "rule_name": "PII_CCCD", "rule_type": "REGEX", "category": "PII", "severity": "HIGH",
     "pattern": r"(?<!\d)0\d{2}[0-3]\d{8}(?!\d)"},
    {"id": 2, "rule_name": "PII_PHONE_VN", "rule_type": "REGEX", "category": "PII", "severity": "MEDIUM",
     "pattern": r"(?<![\d+])(?:\+?84|0)(?:3[2-9]|5[25689]|7[06-9]|8[1-9]|9\d)(?:[ .-]?\d){7}(?!\d)"},
    {"id": 3, "rule_name": "PII_EMAIL", "rule_type": "REGEX", "category": "PII", "severity": "LOW",
     "pattern": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"},
    {"id": 4, "rule_name": "FINANCE_CREDIT_CARD", "rule_type": "REGEX", "category": "FINANCE",
     "severity": "CRITICAL", "pattern": r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"},
    {"id": 5, "rule_name": "INTERNAL_LABEL", "rule_type": "DICTIONARY", "category": "INTERNAL_DOC",
     "severity": "HIGH",
     "pattern": "Tuyệt mật,Tối mật,Tài liệu mật,Lưu hành nội bộ,Confidential,"
                "Strictly Confidential,Internal Use Only,Restricted"},
]
DEFAULT_FILE_TYPES = [
    {"extension": ext, "always_block_regardless_content": True}
    for ext in ("sql", "bak", "sqlite", "mdb", "accdb", "exe", "dll", "msi", "zip", "rar", "7z")
]


# ============================================================================
# 2. TIỆN ÍCH CHUỖI
# ============================================================================
def _nfc(s):
    return unicodedata.normalize("NFC", s)


def fold_accents(s):
    """'Tuyệt Mật' -> 'tuyet mat' (bỏ dấu tiếng Việt, chữ thường)."""
    s = unicodedata.normalize("NFD", s.casefold())
    s = "".join(ch for ch in s if unicodedata.category(ch) != "Mn")
    return s.replace("đ", "d")


def _digits(s):
    return re.sub(r"\D", "", s)


def mask_value(value):
    """Che giá trị nhạy cảm trước khi ghi log: log DLP không được làm lộ chính dữ liệu."""
    value = value.strip()
    if "@" in value:
        local, domain = value.split("@", 1)
        return local[:1] + "***@" + domain
    d = _digits(value)
    if len(d) >= 8:
        return d[:3] + "*" * (len(d) - 5) + d[-2:]
    return value[:2] + "***"


# ============================================================================
# 3. VALIDATOR - tầng 2: xác nhận ứng viên regex có thật là dữ liệu hợp lệ
# ============================================================================
def luhn_valid(value):
    d = _digits(value)
    if not 13 <= len(d) <= 19 or len(set(d)) == 1:
        return False
    total = 0
    for i, ch in enumerate(reversed(d)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def cccd_valid(value):
    """12 số: [3 số mã tỉnh][1 số giới tính+thế kỷ][2 số năm sinh][6 số ngẫu nhiên]."""
    d = _digits(value)
    return len(d) == 12 and d[:3] in VN_PROVINCE_CODES and d[3] in "0123"


def phone_valid(value):
    d = _digits(value)
    if d.startswith("84") and len(d) == 11:
        d = "0" + d[2:]
    return len(d) == 10 and bool(_VN_MOBILE_PREFIX.match(d))


def email_valid(value):
    local, _, domain = value.partition("@")
    return bool(local) and ".." not in value and not domain.rsplit(".", 1)[-1].isdigit()


# Từ khoá ngữ cảnh (đã bỏ dấu). Có từ khoá đứng gần -> tăng độ tin cậy (giống Presidio).
_CONTEXT_WORDS = {
    "CCCD": ("cccd", "can cuoc", "cmnd", "dinh danh", "chung minh", "citizen id", "id card"),
    "CARD": ("so the", "the tin dung", "credit", "card", "visa", "mastercard", "jcb", "napas"),
    "PHONE": ("sdt", "dien thoai", "phone", "tel", "mobile", "di dong", "lien he", "zalo"),
    "EMAIL": ("email", "e-mail", "mail", "thu dien tu"),
}


def _rule_kind(rule):
    name = (rule.get("rule_name") or "").upper()
    if "CCCD" in name or "CMND" in name or "CITIZEN" in name:
        return "CCCD"
    if "CARD" in name:
        return "CARD"
    if "PHONE" in name or "SDT" in name:
        return "PHONE"
    if "EMAIL" in name or "MAIL" in name:
        return "EMAIL"
    return None


_VALIDATORS = {"CCCD": cccd_valid, "CARD": luhn_valid, "PHONE": phone_valid, "EMAIL": email_valid}


# ============================================================================
# 4. BIÊN DỊCH RULE (có cache - rule từ server được dùng lại nhiều lần)
# ============================================================================
@lru_cache(maxsize=256)
def _compile_regex(pattern):
    try:
        return re.compile(pattern)
    except re.error:
        return None


@lru_cache(maxsize=256)
def _compile_dictionary(pattern):
    """Trả về list (regex, chạy_trên_text_bỏ_dấu).
    - Từ khoá 1 từ ('Mật'): so khớp CÓ dấu, tránh nhầm 'mắt', 'mất', 'format'.
    - Cụm >= 2 từ ('Tuyệt mật', 'Noi bo'): so khớp KHÔNG dấu, bắt được cả khi gõ thiếu dấu.
    """
    out = []
    for kw in (k.strip() for k in pattern.split(",")):
        if not kw:
            continue
        if len(kw.split()) >= 2:
            body, on_folded = fold_accents(kw), True
        else:
            body, on_folded = _nfc(kw).casefold(), False
        body = r"\s+".join(re.escape(part) for part in body.split())
        out.append((re.compile(r"(?<!\w)" + body + r"(?!\w)"), on_folded))
    return tuple(out)


# ============================================================================
# 5. NHẬN DIỆN LOẠI FILE THẬT (magic number)
# ============================================================================
_SQL_LINE = re.compile(r"(?im)^\s*(?:create\s+table|insert\s+into|drop\s+table|alter\s+table|"
                       r"create\s+database|lock\s+tables)\b")


def _looks_utf16le(data):
    sample = data[:4000]
    return len(sample) >= 8 and sample[1::2].count(0) > len(sample) // 4


def _looks_like_text(data):
    sample = data[:8192]
    if not sample:
        return True
    if sample.startswith((codecs.BOM_UTF8, codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return True
    if _looks_utf16le(sample):
        return True
    if b"\x00" in sample:
        return False
    ctrl = sum(1 for b in sample if b < 32 and b not in (9, 10, 12, 13))
    return ctrl / len(sample) < 0.05


def detect_file_type(data, declared_ext=""):
    """Xác định loại file theo nội dung (không tin đuôi file)."""
    declared_ext = (declared_ext or "").lower().lstrip(".")
    if data.startswith(b"%PDF-"):
        return "pdf"
    if data.startswith(b"MZ"):
        return declared_ext if declared_ext in EXECUTABLE_EXTS else "exe"
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                names = set(zf.namelist())
        except zipfile.BadZipFile:
            return "zip"
        if "word/document.xml" in names:
            return "docx"
        if "xl/workbook.xml" in names:
            return "xlsx"
        if "ppt/presentation.xml" in names:
            return "pptx"
        return "zip"
    if data.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):  # OLE2: Office 97-2003
        head = data[:200_000]
        if "EncryptedPackage".encode("utf-16-le") in head:
            return "office_encrypted"  # docx/xlsx đặt mật khẩu được bọc trong OLE2
        if declared_ext in ("doc", "xls", "ppt", "msg"):
            return declared_ext
        if "WordDocument".encode("utf-16-le") in head:
            return "doc"
        if "Workbook".encode("utf-16-le") in head:
            return "xls"
        if "PowerPoint Document".encode("utf-16-le") in head:
            return "ppt"
        return "ole"
    signatures = (
        (b"Rar!\x1a\x07", "rar"), (b"7z\xbc\xaf\x27\x1c", "7z"), (b"\x1f\x8b", "gz"),
        (b"SQLite format 3\x00", "sqlite"), (b"\x89PNG\r\n\x1a\n", "png"),
        (b"\xff\xd8\xff", "jpg"), (b"GIF87a", "gif"), (b"GIF89a", "gif"),
    )
    for sig, ftype in signatures:
        if data.startswith(sig):
            return ftype
    if _looks_like_text(data):
        if len(_SQL_LINE.findall(_decode_text(data[:200_000]))) >= 2:
            return "sql"  # dump SQL dù bị đổi đuôi thành .txt
        return declared_ext if declared_ext in TEXT_EXTS else "txt"
    return "bin"


# ============================================================================
# 6. TRÍCH XUẤT TEXT
# ============================================================================
def _decode_text(data):
    if data.startswith(codecs.BOM_UTF8):
        return data[3:].decode("utf-8", "ignore")
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return data.decode("utf-16", "ignore")
    if _looks_utf16le(data):
        return data.decode("utf-16-le", "ignore")
    text = data.decode("utf-8", "replace")
    if text.count("\ufffd") <= max(2, len(text) // 1000):
        return _nfc(text.replace("\ufffd", ""))
    return _nfc(data.decode("cp1258", "replace"))  # Windows ANSI tiếng Việt


_TAG_RE = re.compile(r"<[^>]+>")


def _xml_text(xml_bytes):
    """Lấy text từ XML của Office: xuống dòng theo đoạn/hàng, tab giữa các ô."""
    s = xml_bytes.decode("utf-8", "ignore")
    s = re.sub(r"</(?:w:p|a:p)>", "\n", s)
    s = re.sub(r"<(?:w:tab|w:br|a:br)\b[^>]*/>", " ", s)
    s = re.sub(r"</w:tc>", "\t", s)
    return html.unescape(_TAG_RE.sub("", s))


def _safe_read_member(zf, info, notes):
    if info.file_size > MAX_ZIP_MEMBER_BYTES:
        notes.append("MEMBER_TOO_LARGE:" + info.filename)
        return None
    if info.compress_size and info.file_size / info.compress_size > MAX_ZIP_RATIO:
        notes.append("ZIP_BOMB_SUSPECT:" + info.filename)
        return None
    return zf.read(info)


def _extract_docx_pptx(zf, ftype, notes):
    if ftype == "docx":
        wanted = re.compile(r"^word/(document|header\d*|footer\d*|footnotes|endnotes|comments)\.xml$")
    else:
        wanted = re.compile(r"^ppt/(slides/slide\d+|notesSlides/notesSlide\d+)\.xml$")
    parts = []
    for info in zf.infolist():
        if wanted.match(info.filename):
            raw = _safe_read_member(zf, info, notes)
            if raw:
                parts.append(_xml_text(raw))
    return "\n".join(parts)


_SI_RE = re.compile(r"<si>(.*?)</si>", re.S)
_ROW_RE = re.compile(r"<row\b[^>]*>(.*?)</row>", re.S)
_CELL_RE = re.compile(r"<c\b([^>]*?)(?:/>|>(.*?)</c>)", re.S)
_V_RE = re.compile(r"<v>(.*?)</v>", re.S)


def _extract_xlsx(zf, notes):
    shared = []
    try:
        raw = _safe_read_member(zf, zf.getinfo("xl/sharedStrings.xml"), notes)
        if raw:
            shared = [html.unescape(_TAG_RE.sub("", m)) for m in _SI_RE.findall(raw.decode("utf-8", "ignore"))]
    except KeyError:
        pass
    lines = []
    for info in zf.infolist():
        if not re.match(r"^xl/worksheets/sheet\d+\.xml$", info.filename):
            continue
        raw = _safe_read_member(zf, info, notes)
        if not raw:
            continue
        for row in _ROW_RE.findall(raw.decode("utf-8", "ignore")):
            cells = []
            for attrs, inner in _CELL_RE.findall(row):
                inner = inner or ""
                v = _V_RE.search(inner)
                if 't="s"' in attrs and v:
                    idx = int(v.group(1))
                    cells.append(shared[idx] if idx < len(shared) else "")
                elif 't="inlineStr"' in attrs:
                    cells.append(html.unescape(_TAG_RE.sub("", inner)))
                elif v:
                    cells.append(html.unescape(v.group(1)))
            lines.append("\t".join(cells))
    return "\n".join(lines)


def _extract_pdf(data, notes):
    try:
        from pypdf import PdfReader
    except ImportError:
        try:
            from PyPDF2 import PdfReader
        except ImportError:
            notes.append("PDF_LIB_MISSING")
            return None, False
    try:
        reader = PdfReader(io.BytesIO(data))
        if reader.is_encrypted:
            try:
                ok = reader.decrypt("")  # PDF chỉ có owner-password vẫn mở được
            except Exception:
                ok = 0
            if not ok:
                return None, True
        parts, total = [], 0
        for i, page in enumerate(reader.pages):
            if i >= MAX_PDF_PAGES or total > MAX_TEXT_CHARS:
                notes.append("PDF_TRUNCATED")
                break
            t = page.extract_text() or ""
            parts.append(t)
            total += len(t)
        text = "\n".join(parts)
        if not text.strip():
            notes.append("PDF_NO_TEXT_LAYER")  # PDF scan ảnh -> cần OCR
        return text, False
    except Exception as e:
        notes.append("PDF_PARSE_ERROR:" + type(e).__name__)
        return None, False


_ASCII_RUN = re.compile(rb"[\x20-\x7e\t]{4,}")
_UTF16_RUN = re.compile("[\u0020-\u007e\u00c0-\u024f\u0300-\u036f\u1e00-\u1eff]{4,}")


def _extract_binary_strings(data):
    """Best-effort cho .doc/.xls cũ và file nhị phân lạ: giống lệnh `strings`."""
    data = data[:MAX_TEXT_READ_BYTES]
    parts = [m.decode("ascii") for m in _ASCII_RUN.findall(data)]
    parts += _UTF16_RUN.findall(data.decode("utf-16-le", "ignore"))
    return "\n".join(parts)


def _extract(data, ftype, notes, depth=0):
    """Trả về (text | None, encrypted: bool, member_types: list)."""
    if ftype in TEXT_EXTS or ftype == "sql":
        return _decode_text(data[:MAX_TEXT_READ_BYTES]), False, []
    if ftype == "office_encrypted":
        return None, True, []
    if ftype == "pdf":
        text, enc = _extract_pdf(data, notes)
        return text, enc, []
    if ftype in ("docx", "pptx", "xlsx", "zip"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                if any(i.flag_bits & 0x1 for i in zf.infolist()):
                    return None, True, []  # zip đặt mật khẩu
                if ftype == "xlsx":
                    return _extract_xlsx(zf, notes), False, []
                if ftype in ("docx", "pptx"):
                    return _extract_docx_pptx(zf, ftype, notes), False, []
                return _extract_archive(zf, notes, depth)
        except (zipfile.BadZipFile, RuntimeError, ValueError, OSError):
            notes.append("ZIP_CORRUPT")
            return None, False, []
    if ftype in ("doc", "xls", "ppt", "ole", "bin", "sqlite"):
        notes.append("BEST_EFFORT_STRINGS")
        return _extract_binary_strings(data), False, []
    if ftype in ("png", "jpg", "gif", "bmp"):
        notes.append("IMAGE_NO_OCR")
    elif ftype in ("rar", "7z", "gz"):
        notes.append("ARCHIVE_UNSUPPORTED")
    return None, False, []


def _extract_archive(zf, notes, depth):
    """Quét 1 cấp các file bên trong .zip (bắt trò nén .sql/.xlsx vào zip để lách)."""
    texts, member_types = [], []
    members = [i for i in zf.infolist() if not i.is_dir()]
    if len(members) > MAX_ARCHIVE_MEMBERS:
        notes.append("ARCHIVE_TRUNCATED")
    for info in members[:MAX_ARCHIVE_MEMBERS]:
        raw = _safe_read_member(zf, info, notes)
        if raw is None:
            continue
        ext = os.path.splitext(info.filename)[1].lower().lstrip(".")
        mtype = detect_file_type(raw, ext)
        member_types.append({"name": info.filename, "declared_ext": ext, "real_type": mtype})
        if mtype == "zip" and depth >= 1:
            notes.append("NESTED_ARCHIVE_SKIPPED:" + info.filename)
            continue
        text, enc, sub_types = _extract(raw, mtype, notes, depth + 1)
        member_types.extend(sub_types)
        if enc:
            return None, True, member_types
        if text:
            texts.append(text)
    return "\n".join(texts), False, member_types


# ============================================================================
# 7. QUÉT NỘI DUNG + CHẤM ĐIỂM
# ============================================================================
def _has_context(text, start, kind):
    words = _CONTEXT_WORDS.get(kind)
    if not words:
        return False
    window = fold_accents(text[max(0, start - CONTEXT_WINDOW):start])
    return any(w in window for w in words)


def _scan_rule(rule, text, text_cf, text_folded):
    """Trả về chi tiết match của 1 rule, hoặc None nếu không match."""
    rtype = (rule.get("rule_type") or "REGEX").upper()
    pattern = rule.get("pattern") or ""
    total, values, samples, context = 0, set(), [], False

    if rtype == "DICTIONARY":
        for rx, on_folded in _compile_dictionary(pattern):
            for m in rx.finditer(text_folded if on_folded else text_cf):
                total += 1
                values.add(m.group(0))
                if total >= MAX_MATCHES_PER_RULE:
                    break
        context = total > 0  # nhãn mật là dấu hiệu có chủ đích, không cần ngữ cảnh
        samples = sorted(values)[:SAMPLES_PER_RULE]
    else:
        rx = _compile_regex(pattern)
        if rx is None:
            return None
        kind = _rule_kind(rule)
        validator = _VALIDATORS.get(kind)
        for m in rx.finditer(text):
            value = m.group(0)
            if validator and not validator(value):
                continue  # regex khớp nhưng không phải dữ liệu thật -> bỏ (giảm false positive)
            total += 1
            norm = _digits(value) if kind in ("CCCD", "CARD", "PHONE") else value.lower()
            if norm not in values:
                values.add(norm)
                if len(samples) < SAMPLES_PER_RULE:
                    samples.append(mask_value(value))
            if not context and _has_context(text, m.start(), kind):
                context = True
            if total >= MAX_MATCHES_PER_RULE:
                break

    if total == 0:
        return None
    return {"rule_id": rule.get("id"), "rule_name": rule.get("rule_name"),
            "rule_type": rtype, "category": rule.get("category"),
            "severity": (rule.get("severity") or "LOW").upper(),
            "total": total, "unique": len(values), "context": context, "samples": samples}


def _score(hits, extension_mismatch=False):
    """Confidence Scoring - từng bước đều ghi lý do để giải thích được kết quả.

    Mức gốc = severity của rule, sau đó:
      * >= BULK_THRESHOLD giá trị khác nhau          -> +1 (dữ liệu hàng loạt, nghi cố ý)
      * chỉ 1 giá trị, không có từ khoá ngữ cảnh     -> -1 (có thể chỉ là con số trùng hợp)
    Mức tổng = mức cao nhất trong các rule, sau đó:
      * >= 2 nhóm dữ liệu (VD: PII + FINANCE)         -> +1 (hồ sơ khách hàng hoàn chỉnh)
      * file bị đổi đuôi so với loại thật             -> +1 (dấu hiệu cố tình che giấu)
    """
    reasons, best = [], -1
    for h in hits:
        lvl = _LEVEL_IDX.get(h["severity"], 0)
        if h["unique"] >= BULK_THRESHOLD:
            lvl += 1
            reasons.append("%s: %d gia tri khac nhau (>= %d) -> +1" % (h["rule_name"], h["unique"], BULK_THRESHOLD))
        elif h["unique"] == 1 and not h["context"] and h["rule_type"] == "REGEX":
            lvl -= 1
            reasons.append("%s: chi 1 gia tri, khong co ngu canh -> -1" % h["rule_name"])
        lvl = max(0, min(lvl, 3))
        h["level"] = LEVELS[lvl]
        best = max(best, lvl)
    if best < 0:
        return "LOW", reasons
    categories = {h["category"] for h in hits if h.get("category")}
    if len(categories) >= 2:
        best += 1
        reasons.append("Ket hop %d nhom du lieu (%s) -> +1" % (len(categories), ", ".join(sorted(categories))))
    if extension_mismatch:
        best += 1
        reasons.append("File bi doi duoi so voi loai that -> +1")
    return LEVELS[min(best, 3)], reasons


def scan_text(text, rules, extension_mismatch=False):
    """Quét 1 đoạn text (dùng trực tiếp cho Clipboard)."""
    started = time.perf_counter()
    text = _nfc(text or "")[:MAX_TEXT_CHARS]
    hits = []
    if text and rules:
        text_cf = text.casefold()
        text_folded = fold_accents(text)
        for rule in rules:
            hit = _scan_rule(rule, text, text_cf, text_folded)
            if hit:
                hits.append(hit)
    level, reasons = _score(hits, extension_mismatch) if hits else ("LOW", [])
    return {
        "matched_rule_ids": [h["rule_id"] for h in hits],
        "matched_rule_names": [h["rule_name"] for h in hits],
        "confidence_level": level,
        "match_count": sum(h["total"] for h in hits),
        "rule_details": hits,
        "score_reasons": reasons,
        "scan_ms": round((time.perf_counter() - started) * 1000, 1),
    }


def scan_content_with_rules(text, rules):
    """Giữ nguyên tên hàm cũ của stub để network_agent/sftp_scp_agent không phải sửa."""
    return scan_text(text, rules)


# ============================================================================
# 8. QUYẾT ĐỊNH CHO 1 FILE
# ============================================================================
def sha256_file(path):
    try:
        if os.path.getsize(path) > MAX_HASH_BYTES:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _read_file(path, size, retries=3):
    """File có thể đang bị tiến trình khác ghi/khoá (đang copy ra USB) -> thử lại vài lần."""
    limit = size if size <= MAX_FILE_BYTES else MAX_TEXT_READ_BYTES
    for attempt in range(retries):
        try:
            with open(path, "rb") as f:
                return f.read(limit)
        except PermissionError:
            if attempt == retries - 1:
                raise
            time.sleep(0.3)
    return b""


def _norm_path(p):
    return os.path.normcase(os.path.normpath(str(p))) if p else ""


def _is_exception(path, destination, allowed_files, allowed_locations):
    p, name = _norm_path(path), os.path.basename(path).lower()
    for f in allowed_files or []:
        if _norm_path(f) == p or str(f).strip().lower() == name:
            return "ALLOWED_FILE"
    for loc in allowed_locations or []:
        loc_n = _norm_path(loc)
        for candidate in (p, _norm_path(destination)):
            if candidate and (candidate == loc_n or candidate.startswith(loc_n.rstrip("\\/") + os.sep)):
                return "ALLOWED_LOCATION"
    return None


def _blocked_types(file_types):
    return {str(ft.get("extension", "")).lower().lstrip(".")
            for ft in (file_types or []) if ft.get("always_block_regardless_content")}


def _verdict_for_violation(action):
    return "BLOCK" if action == "BLOCK" else "LOG"


def inspect_file(path, status=None, rules=None, file_types=None, destination=None):
    """Kiểm tra 1 file trước khi cho phép nó đi qua exit point.

    path        : đường dẫn file cần kiểm tra
    status      : kết quả policy_utils.get_exit_point_status(...) cho exit point đang xét.
                  Nếu None -> dùng DEFAULT_RULES/DEFAULT_FILE_TYPES, action = BLOCK (chế độ test).
    rules, file_types : ghi đè rule/loại file (tuỳ chọn)
    destination : đích đến (IP:port, ổ USB...) - dùng cho kiểm tra allowed_locations

    Trả về dict, trong đó 'verdict' là ALLOW | LOG | BLOCK.
    Agent tự đổi verdict BLOCK thành action_taken của kênh mình
    (USB -> BLOCKED_DELETE, SCP/SFTP -> BLOCKED_KILL, Web -> BLOCKED_FIREWALL).
    """
    started = time.perf_counter()
    if status is None:
        status = {"is_governed": True, "effective_action": "BLOCK",
                  "content_rules": DEFAULT_RULES, "file_types": DEFAULT_FILE_TYPES}
    action = status.get("effective_action", "OPEN") if status.get("is_governed") else "OPEN"
    rules = status.get("content_rules") if rules is None else rules
    file_types = status.get("file_types") if file_types is None else file_types

    path = str(path)
    declared_ext = os.path.splitext(path)[1].lower().lstrip(".")
    result = {
        "verdict": "ALLOW", "reason": "CLEAN", "reasons": [], "notes": [],
        "file_path": path, "file_name": os.path.basename(path), "file_size": None,
        "file_hash_sha256": None, "declared_ext": declared_ext, "real_type": None,
        "category": None, "extension_mismatch": False, "encrypted": False, "inspected": False,
        "policy_action": action, "matched_rule_ids": [], "matched_rule_names": [],
        "confidence_level": "LOW", "match_count": 0, "rule_details": [], "scan_ms": 0.0,
    }

    def done(verdict, reason, confidence=None, extra_reason=None):
        result["verdict"], result["reason"] = verdict, reason
        if confidence:
            result["confidence_level"] = confidence
        if extra_reason:
            result["reasons"].append(extra_reason)
        result["scan_ms"] = round((time.perf_counter() - started) * 1000, 1)
        return result

    if action == "OPEN":
        return done("ALLOW", "NOT_GOVERNED")

    exc = _is_exception(path, destination, status.get("allowed_files"), status.get("allowed_locations"))
    if exc:
        return done("ALLOW", exc, extra_reason="Nam trong danh sach ngoai le cua policy")

    try:
        size = os.path.getsize(path)
        data = _read_file(path, size)
    except OSError as e:
        result["notes"].append("READ_ERROR:" + type(e).__name__)
        # Không đọc được file thì không chứng minh được là sạch -> fail-closed khi BLOCK
        return done(_verdict_for_violation(action), "UNREADABLE", "MEDIUM",
                    "Khong doc duoc file (%s)" % type(e).__name__)
    result["file_size"] = size
    result["file_hash_sha256"] = sha256_file(path)

    real_type = detect_file_type(data, declared_ext)
    result["real_type"] = real_type
    result["category"] = _CATEGORY.get(real_type, "OTHER")
    text_family = TEXT_EXTS | {"sql"}
    ext_norm = _EXT_ALIASES.get(declared_ext, declared_ext)
    same_family = (real_type == ext_norm or (real_type in text_family and ext_norm in text_family)
                   or (real_type == "exe" and ext_norm in EXECUTABLE_EXTS))
    result["extension_mismatch"] = bool(declared_ext) and not same_family
    if result["extension_mismatch"]:
        result["reasons"].append("Duoi file '.%s' nhung noi dung that la '%s'" % (declared_ext, real_type))

    # --- File Type Control ---
    blocked = _blocked_types(file_types)
    hit_type = declared_ext if declared_ext in blocked else (real_type if real_type in blocked else None)
    if hit_type:
        return done(_verdict_for_violation(action), "FILE_TYPE_BLOCKED", "HIGH",
                    "Loai file '%s' nam trong danh sach luon chan" % hit_type)

    # --- Không có content rule: chặn hoàn toàn (BLOCKED) hoặc chỉ giám sát (MONITORED) ---
    if not rules:
        if action == "BLOCK":
            return done("BLOCK", "EXIT_POINT_BLOCKED", "HIGH", "Policy chan toan bo kenh nay")
        return done("LOG", "EXIT_POINT_MONITORED", extra_reason="Kenh o che do giam sat, ghi nhan moi file")

    if size > MAX_FILE_BYTES and real_type not in text_family:
        result["notes"].append("TOO_LARGE")
        verdict = _verdict_for_violation(action) if BLOCK_TOO_LARGE else "LOG"
        return done(verdict, "TOO_LARGE", "MEDIUM", "File qua lon de quet noi dung")

    # --- Trích xuất nội dung ---
    text, encrypted, member_types = _extract(data, real_type, result["notes"])
    result["encrypted"] = encrypted
    for m in member_types:
        if m["declared_ext"] in blocked or m["real_type"] in blocked:
            return done(_verdict_for_violation(action), "FILE_TYPE_BLOCKED", "HIGH",
                        "File nen chua '%s' (loai bi chan)" % m["name"])
    if encrypted:
        verdict = _verdict_for_violation(action) if BLOCK_ENCRYPTED else "LOG"
        return done(verdict, "ENCRYPTED_CONTENT", "HIGH",
                    "File ma hoa/dat mat khau - khong the kiem tra noi dung")
    if text is None:
        return done("ALLOW", "NOT_INSPECTABLE", extra_reason="Khong trich xuat duoc noi dung de quet")

    # --- Quét + chấm điểm ---
    result["inspected"] = True
    scan = scan_text(text, rules, result["extension_mismatch"])
    for key in ("matched_rule_ids", "matched_rule_names", "confidence_level", "match_count", "rule_details"):
        result[key] = scan[key]
    result["reasons"].extend(scan["score_reasons"])
    if not scan["matched_rule_ids"]:
        return done("ALLOW", "CLEAN")
    if action == "BLOCK" and _LEVEL_IDX[scan["confidence_level"]] >= _LEVEL_IDX[BLOCK_MIN_LEVEL]:
        return done("BLOCK", "CONTENT_MATCH")
    return done("LOG", "CONTENT_MATCH")


# ============================================================================
# 9. CHUYỂN KẾT QUẢ SANG ĐỊNH DẠNG LOG / REPORT
# ============================================================================
def to_log_inspection(result):
    """Phần 'content_inspection' trong log JSON gửi Wazuh (đã che dữ liệu nhạy cảm)."""
    return {
        "matched_rule_ids": result.get("matched_rule_ids", []),
        "matched_rule_names": result.get("matched_rule_names", []),
        "confidence_level": result.get("confidence_level", "LOW"),
        "match_count": result.get("match_count", 0),
        "verdict": result.get("verdict"),
        "reason": result.get("reason"),
        "real_file_type": result.get("real_type"),
        "extension_mismatch": result.get("extension_mismatch", False),
        "encrypted": result.get("encrypted", False),
        "masked_samples": {h["rule_name"]: h["samples"] for h in result.get("rule_details", [])},
        "scan_ms": result.get("scan_ms"),
    }


def to_report_fields(result):
    """Các trường dùng cho POST agent_report.php."""
    matched = bool(result.get("matched_rule_ids")) or result.get("reason") != "CLEAN"
    return {
        "file_path": result.get("file_path"),
        "file_hash_sha256": result.get("file_hash_sha256"),
        "matched_rule_ids": result.get("matched_rule_ids", []),
        "confidence_score": result.get("confidence_level") if matched else None,
    }


# ============================================================================
# 10. CHẠY THỬ TỪ DÒNG LỆNH
# ============================================================================
def _main(argv):
    import argparse
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    ap = argparse.ArgumentParser(description="Quet thu file bang Content Inspection Engine")
    ap.add_argument("files", nargs="+", help="file, thu muc hoac mau *.docx")
    ap.add_argument("--rules", help="file JSON chua danh sach rule (mac dinh: DEFAULT_RULES)")
    ap.add_argument("--action", default="BLOCK", choices=["BLOCK", "REPORT_ONLY"])
    ap.add_argument("--full", action="store_true", help="in toan bo ket qua")
    args = ap.parse_args(argv)
    rules = DEFAULT_RULES
    if args.rules:
        with open(args.rules, encoding="utf-8") as f:
            rules = json.load(f)
    status = {"is_governed": True, "effective_action": args.action,
              "content_rules": rules, "file_types": DEFAULT_FILE_TYPES}
    import glob
    paths = []
    for arg in args.files:  # Windows không tự mở rộng dấu *, và cho phép truyền cả thư mục
        if os.path.isdir(arg):
            paths += sorted(os.path.join(arg, n) for n in os.listdir(arg)
                            if os.path.isfile(os.path.join(arg, n)))
        elif any(ch in arg for ch in "*?["):
            paths += sorted(glob.glob(arg))
        else:
            paths.append(arg)
    for fp in paths:
        r = inspect_file(fp, status)
        if args.full:
            print(json.dumps(r, ensure_ascii=False, indent=2))
            continue
        print("%-6s %-18s %-8s %-28s %6sms  %s" % (
            r["verdict"], r["reason"], r["confidence_level"], ",".join(r["matched_rule_names"]) or "-",
            r["scan_ms"], r["file_name"]))
        for reason in r["reasons"]:
            print("       - " + reason)


if __name__ == "__main__":
    _main(sys.argv[1:])
