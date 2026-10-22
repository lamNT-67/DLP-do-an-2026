"""
Tạo bộ file mẫu để test / demo Content Inspection Engine.
Chỉ dùng thư viện chuẩn của Python -> chạy được trên mọi máy Windows có Python.

    python make_samples.py              -> tạo thư mục dlp_samples/ cạnh file này
    python make_samples.py D:\\demo      -> tạo vào thư mục chỉ định
    python make_samples.py --big=20     -> thêm 1 file CSV 20 MB để demo chặn SCP/SFTP

TOÀN BỘ dữ liệu là GIẢ (số thẻ là số test công khai của Visa/Mastercard).
"""

import io
import os
import random
import sys
import zipfile
from xml.sax.saxutils import escape

PROVINCES = ["001", "024", "031", "036", "038", "040", "046", "048", "079", "092"]
HO = ["Nguyễn", "Trần", "Lê", "Phạm", "Hoàng", "Vũ", "Đặng", "Bùi", "Đỗ", "Ngô"]
TEN = ["Văn An", "Thị Bình", "Minh Châu", "Quốc Dũng", "Thu Hà", "Gia Huy", "Ngọc Lan",
       "Đức Long", "Thanh Mai", "Hoài Nam", "Bảo Ngọc", "Tuấn Phong", "Kim Oanh", "Hữu Tài"]
TEST_CARDS = ["4111 1111 1111 1111", "5555 5555 5555 4444", "4012 8888 8888 1881",
              "5105 1051 0510 5100", "3530 1113 3330 0000"]


def fake_cccd(rng):
    """[mã tỉnh][giới tính + thế kỷ][năm sinh][6 số]: 0/1 = nam/nữ sinh 19xx, 2/3 = nam/nữ sinh 20xx."""
    century = rng.choice("0123")
    year = rng.randint(60, 99) if century in "01" else rng.randint(0, 7)
    return rng.choice(PROVINCES) + century + "%02d" % year + "%06d" % rng.randint(0, 999999)


def fake_phone(rng):
    return "0" + rng.choice(["32", "35", "38", "39", "56", "70", "77", "86", "90", "91", "98"]) + \
        "%07d" % rng.randint(0, 9999999)


def fake_people(n, seed=7):
    rng = random.Random(seed)
    people = []
    for i in range(n):
        name = "%s %s" % (rng.choice(HO), rng.choice(TEN))
        people.append({
            "name": name, "cccd": fake_cccd(rng), "phone": fake_phone(rng),
            "email": "khachhang%03d@example.com" % (i + 1),
            "card": TEST_CARDS[i % len(TEST_CARDS)],
        })
    return people


# ---------------------------------------------------------------- Office builders
_RELS = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
         '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
         '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
         'relationships/officeDocument" Target="%s"/></Relationships>')


def build_docx(paragraphs, split_runs=False):
    """paragraphs: list[str]. split_runs=True: cắt mỗi đoạn thành nhiều run như Word thật."""
    body = []
    for p in paragraphs:
        if split_runs and len(p) > 6:
            mid = len(p) // 2
            runs = [p[:mid], p[mid:]]
        else:
            runs = [p]
        body.append("<w:p>" + "".join('<w:r><w:t xml:space="preserve">%s</w:t></w:r>' % escape(r)
                                     for r in runs) + "</w:p>")
    doc = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
           '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
           '<w:body>%s</w:body></w:document>' % "".join(body))
    ct = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
          '<Default Extension="xml" ContentType="application/xml"/>'
          '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-'
          'officedocument.wordprocessingml.document.main+xml"/></Types>')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", ct)
        z.writestr("_rels/.rels", _RELS % "word/document.xml")
        z.writestr("word/document.xml", doc)
    return buf.getvalue()


def _col(i):
    s = ""
    i += 1
    while i:
        i, r = divmod(i - 1, 26)
        s = chr(65 + r) + s
    return s


def build_xlsx(rows):
    """rows: list[list[str]]. Mọi ô ghi dạng shared string (giống Excel khi nhập text)."""
    shared, index = [], {}
    sheet_rows = []
    for r, row in enumerate(rows, start=1):
        cells = []
        for c, value in enumerate(row):
            value = str(value)
            if value not in index:
                index[value] = len(shared)
                shared.append(value)
            cells.append('<c r="%s%d" t="s"><v>%d</v></c>' % (_col(c), r, index[value]))
        sheet_rows.append('<row r="%d">%s</row>' % (r, "".join(cells)))
    ns = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
    sheet = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet %s>'
             '<sheetData>%s</sheetData></worksheet>' % (ns, "".join(sheet_rows)))
    sst = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><sst %s count="%d" uniqueCount="%d">%s</sst>'
           % (ns, len(shared), len(shared), "".join('<si><t xml:space="preserve">%s</t></si>' % escape(s)
                                                       for s in shared)))
    workbook = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook %s '
                'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                '<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>' % ns)
    wb_rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
               '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
               '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
               'relationships/worksheet" Target="worksheets/sheet1.xml"/>'
               '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
               'relationships/sharedStrings" Target="sharedStrings.xml"/></Relationships>')
    ct = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
          '<Default Extension="xml" ContentType="application/xml"/>'
          '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-'
          'officedocument.spreadsheetml.sheet.main+xml"/>'
          '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-'
          'officedocument.spreadsheetml.worksheet+xml"/>'
          '<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-'
          'officedocument.spreadsheetml.sharedStrings+xml"/></Types>')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", ct)
        z.writestr("_rels/.rels", _RELS % "xl/workbook.xml")
        z.writestr("xl/workbook.xml", workbook)
        z.writestr("xl/_rels/workbook.xml.rels", wb_rels)
        z.writestr("xl/worksheets/sheet1.xml", sheet)
        z.writestr("xl/sharedStrings.xml", sst)
    return buf.getvalue()


def build_pdf(lines):
    """PDF 1 trang tối giản (chỉ ASCII), đủ để pypdf trích text."""
    content = "BT /F1 11 Tf 50 800 Td 14 TL " + " ".join(
        "(%s) Tj T*" % l.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)") for l in lines) + " ET"
    objs = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> "
        "/Contents 5 0 R >>",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        "<< /Length %d >>\nstream\n%s\nendstream" % (len(content), content),
    ]
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(out.tell())
        out.write(("%d 0 obj\n%s\nendobj\n" % (i, body)).encode("latin-1"))
    xref = out.tell()
    out.write(("xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)).encode())
    for off in offsets:
        out.write(("%010d 00000 n \n" % off).encode())
    out.write(("trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)).encode())
    return out.getvalue()


def build_zip(members):
    """members: dict tên_file -> bytes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members.items():
            z.writestr(name, data)
    return buf.getvalue()


def mark_zip_encrypted(data):
    """Bật cờ 'encrypted' trong header zip -> giả lập file zip đặt mật khẩu (chỉ dùng để test).
    Demo thật: tạo zip có mật khẩu bằng 7-Zip trên Windows."""
    b = bytearray(data)
    for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        i = b.find(sig)
        while i != -1:
            b[i + off] |= 0x01
            i = b.find(sig, i + 4)
    return bytes(b)


FAKE_EXE = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"\x00" * 48 + \
    b"This program cannot be run in DOS mode.\r\n" + b"\x00" * 200


# ---------------------------------------------------------------- Bộ demo
def make_demo_set(out_dir):
    os.makedirs(out_dir, exist_ok=True)
    people = fake_people(20)
    files = {}

    header = ["Họ tên", "Số CCCD", "Số điện thoại", "Email", "Số thẻ"]
    rows = [header] + [[p["name"], p["cccd"], p["phone"], p["email"], p["card"]] for p in people]
    files["01_danh_sach_khach_hang.xlsx"] = build_xlsx(rows)

    files["02_hop_dong_tuyet_mat.docx"] = build_docx([
        "CÔNG TY CỔ PHẦN ABC - TÀI LIỆU TUYỆT MẬT",
        "Hợp đồng hợp tác chiến lược năm 2026",
        "Đại diện bên B: %s, số CCCD: %s" % (people[0]["name"], people[0]["cccd"]),
    ], split_runs=True)

    files["03_bao_cao_tuan_sach.docx"] = build_docx([
        "Báo cáo tiến độ tuần 43",
        "Nhóm đã hoàn thành module giao diện, tuần sau tiếp tục kiểm thử.",
        "Số lượng ticket đã xử lý: 128.",
    ])

    files["04_ghi_chu_1_email.txt"] = "Gửi lại tài liệu cho anh qua email lienhe@example.com nhé.\n".encode("utf-8")

    files["05_thong_tin_the.pdf"] = build_pdf([
        "Payment information", "Card number: %s" % TEST_CARDS[0],
        "Card holder CCCD: %s" % people[1]["cccd"],
    ])

    dump = ["-- MySQL dump 10.13", "CREATE TABLE customers (id INT, name VARCHAR(100), cccd CHAR(12));"]
    dump += ["INSERT INTO customers VALUES (%d, 'KH%03d', '%s');" % (i, i, p["cccd"]) for i, p in enumerate(people)]
    files["06_backup_database.sql"] = "\n".join(dump).encode("utf-8")
    files["07_backup_doi_duoi.txt"] = files["06_backup_database.sql"]          # .sql đổi thành .txt
    files["08_anh_chup_man_hinh.jpg"] = files["01_danh_sach_khach_hang.xlsx"]  # .xlsx đổi thành .jpg
    files["09_tai_lieu.txt"] = FAKE_EXE                                          # .exe đổi thành .txt
    files["10_nen_lai_cho_gon.zip"] = build_zip({"data/khach_hang.xlsx": files["01_danh_sach_khach_hang.xlsx"]})
    files["11_ghi_chu_utf16.txt"] = ("Số CCCD của tôi là %s\r\n" % people[2]["cccd"]).encode("utf-16")
    files["12_so_ngau_nhien.txt"] = ("Mã đơn hàng: 999123456789\nMã vận đơn: 4111111111111112\n"
                                     "Hotline tổng đài: 1900 1234\n").encode("utf-8")

    for name, data in files.items():
        with open(os.path.join(out_dir, name), "wb") as f:
            f.write(data)
    return sorted(files)


def make_big_csv(out_dir, megabytes):
    """File CSV lớn để demo chặn SCP/SFTP: file nhỏ truyền xong trước khi agent kịp quét (poll 2s)."""
    people = fake_people(500, seed=11)
    lines = ["ho_ten,cccd,sdt,email,so_the"] + ["%s,%s,%s,%s,%s" % (p["name"], p["cccd"], p["phone"],
                                                                     p["email"], p["card"]) for p in people]
    block = ("\n".join(lines) + "\n").encode("utf-8")
    path = os.path.join(out_dir, "13_xuat_du_lieu_lon.csv")
    with open(path, "wb") as f:
        for _ in range(megabytes * 1024 * 1024 // len(block) + 1):
            f.write(block)
    return os.path.basename(path)


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--big")]
    big = [a for a in sys.argv[1:] if a.startswith("--big")]
    target = args[0] if args else os.path.join(os.path.dirname(os.path.abspath(__file__)), "dlp_samples")
    names = make_demo_set(target)
    if big:
        mb = int(big[0].split("=", 1)[1]) if "=" in big[0] else 20
        names.append(make_big_csv(target, mb))
    print("Da tao %d file mau trong: %s" % (len(names), target))
    for n in names:
        print("  " + n)
