"""
Test tự động cho Content Inspection Engine (chỉ dùng thư viện chuẩn).

    cd agent
    python -m unittest dev_tools.test_content_inspection -v
"""

import os
import shutil
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))  # thư mục agent/
sys.path.insert(0, HERE)

import content_inspection as ci  # noqa: E402
import make_samples as ms  # noqa: E402

try:
    import pypdf  # noqa: F401
    HAS_PDF = True
except ImportError:
    HAS_PDF = False

CCCD_OK = "001203012345"        # mã tỉnh 001 (Hà Nội), hợp lệ
CCCD_BAD_PROVINCE = "999203012345"
CARD_OK = "4111 1111 1111 1111"  # số test công khai của Visa, qua được Luhn
CARD_BAD = "4111 1111 1111 1112"


def status(action="BLOCK", rules=None, file_types=None, **extra):
    s = {"is_governed": True, "effective_action": action,
         "content_rules": ci.DEFAULT_RULES if rules is None else rules,
         "file_types": [] if file_types is None else file_types}
    s.update(extra)
    return s


BLOCK_SQL_EXE = [{"extension": "sql", "always_block_regardless_content": True},
                 {"extension": "exe", "always_block_regardless_content": True}]


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="dlp_test_")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, name, data):
        if isinstance(data, str):
            data = data.encode("utf-8")
        path = os.path.join(self.dir, name)
        with open(path, "wb") as f:
            f.write(data)
        return path


class TestValidators(unittest.TestCase):
    def test_luhn(self):
        self.assertTrue(ci.luhn_valid(CARD_OK))
        self.assertFalse(ci.luhn_valid(CARD_BAD))
        self.assertFalse(ci.luhn_valid("0000000000000000"))

    def test_cccd(self):
        self.assertTrue(ci.cccd_valid(CCCD_OK))
        self.assertFalse(ci.cccd_valid(CCCD_BAD_PROVINCE))
        self.assertFalse(ci.cccd_valid("001903012345"))  # số thứ 4 = 9: không hợp lệ

    def test_phone(self):
        self.assertTrue(ci.phone_valid("0912345678"))
        self.assertTrue(ci.phone_valid("+84 912 345 678"))
        self.assertFalse(ci.phone_valid("0212345678"))

    def test_mask_never_leaks_full_value(self):
        masked = ci.mask_value(CCCD_OK)
        self.assertNotEqual(masked, CCCD_OK)
        self.assertTrue(masked.startswith("001") and masked.endswith("45"))
        self.assertEqual(ci.mask_value("nguyenvana@abc.vn"), "n***@abc.vn")


class TestScanText(unittest.TestCase):
    def test_validator_filters_false_positive(self):
        r = ci.scan_text("Ma don hang %s, ma van don %s" % (CCCD_BAD_PROVINCE, CARD_BAD), ci.DEFAULT_RULES)
        self.assertEqual(r["matched_rule_ids"], [])

    def test_context_keeps_level(self):
        with_ctx = ci.scan_text("So CCCD: " + CCCD_OK, ci.DEFAULT_RULES)
        without = ci.scan_text("Gia tri " + CCCD_OK, ci.DEFAULT_RULES)
        self.assertEqual(with_ctx["confidence_level"], "HIGH")
        self.assertEqual(without["confidence_level"], "MEDIUM")  # 1 số lẻ loi -> hạ 1 mức

    def test_bulk_escalates(self):
        people = ms.fake_people(15)
        text = "\n".join(p["cccd"] for p in people)
        r = ci.scan_text(text, ci.DEFAULT_RULES)
        self.assertEqual(r["confidence_level"], "CRITICAL")

    def test_combination_escalates(self):
        r = ci.scan_text("CCCD %s, so the %s" % (CCCD_OK, CARD_OK), ci.DEFAULT_RULES)
        self.assertEqual(r["confidence_level"], "CRITICAL")
        self.assertEqual(set(r["matched_rule_names"]), {"PII_CCCD", "FINANCE_CREDIT_CARD"})

    def test_dictionary_accent_rules(self):
        self.assertIn(5, ci.scan_text("TÀI LIỆU TUYỆT MẬT", ci.DEFAULT_RULES)["matched_rule_ids"])
        self.assertIn(5, ci.scan_text("tai lieu tuyet mat", ci.DEFAULT_RULES)["matched_rule_ids"])
        # 'mật ong', 'format', 'mất' không được khớp với từ khoá 1 từ 'Mật'
        rules = [{"id": 9, "rule_name": "LBL", "rule_type": "DICTIONARY", "pattern": "Mật",
                  "category": "INTERNAL_DOC", "severity": "HIGH"}]
        self.assertEqual(ci.scan_text("format file, mất điện, mắt kính", rules)["matched_rule_ids"], [])
        self.assertEqual(ci.scan_text("Độ MẬT: cao", rules)["matched_rule_ids"], [9])

    def test_old_server_rules_still_work(self):
        """Rule seed cũ trong schema.sql (regex lỏng) vẫn chạy, validator lọc bớt sai."""
        old = [{"id": 1, "rule_name": "PII_CCCD", "rule_type": "REGEX", "pattern": r"\b\d{12}\b",
                "category": "PII", "severity": "HIGH"},
               {"id": 4, "rule_name": "FINANCE_CREDIT_CARD", "rule_type": "REGEX",
                "pattern": r"\b(?:\d[ -]*?){13,16}\b", "category": "FINANCE", "severity": "CRITICAL"}]
        r = ci.scan_text("%s %s | %s %s" % (CCCD_OK, CCCD_BAD_PROVINCE, CARD_OK, CARD_BAD), old)
        self.assertEqual(sorted(r["matched_rule_ids"]), [1, 4])
        details = {d["rule_name"]: d for d in r["rule_details"]}
        self.assertEqual(details["PII_CCCD"]["unique"], 1)

    def test_backward_compatible_api(self):
        r = ci.scan_content_with_rules("drive.google.com", ci.DEFAULT_RULES)
        for key in ("matched_rule_ids", "matched_rule_names", "confidence_level"):
            self.assertIn(key, r)

    def test_bad_regex_is_skipped(self):
        rules = [{"id": 1, "rule_name": "BROKEN", "rule_type": "REGEX", "pattern": "([",
                  "category": "PII", "severity": "HIGH"}]
        self.assertEqual(ci.scan_text("abc", rules)["matched_rule_ids"], [])


class TestInspectFile(Base):
    def test_clean_docx_allowed(self):
        p = self.write("bao_cao.docx", ms.build_docx(["Bao cao tien do tuan 43"]))
        self.assertEqual(ci.inspect_file(p, status())["verdict"], "ALLOW")

    def test_docx_split_runs(self):
        p = self.write("hd.docx", ms.build_docx(["So CCCD: " + CCCD_OK], split_runs=True))
        r = ci.inspect_file(p, status())
        self.assertEqual(r["verdict"], "BLOCK")
        self.assertIn("PII_CCCD", r["matched_rule_names"])

    def test_xlsx_bulk(self):
        rows = [["Ho ten", "CCCD"]] + [[p["name"], p["cccd"]] for p in ms.fake_people(12)]
        r = ci.inspect_file(self.write("kh.xlsx", ms.build_xlsx(rows)), status())
        self.assertEqual((r["verdict"], r["confidence_level"]), ("BLOCK", "CRITICAL"))
        self.assertEqual(r["real_type"], "xlsx")

    def test_single_email_only_logged(self):
        r = ci.inspect_file(self.write("note.txt", "lien he a@example.com"), status())
        self.assertEqual((r["verdict"], r["confidence_level"]), ("LOG", "LOW"))

    def test_report_only_never_blocks(self):
        r = ci.inspect_file(self.write("x.txt", "CCCD " + CCCD_OK), status("REPORT_ONLY"))
        self.assertEqual(r["verdict"], "LOG")

    def test_not_governed(self):
        p = self.write("x.txt", "CCCD " + CCCD_OK)
        r = ci.inspect_file(p, {"is_governed": False, "effective_action": "OPEN"})
        self.assertEqual(r["verdict"], "ALLOW")

    def test_block_without_rules_blocks_everything(self):
        r = ci.inspect_file(self.write("clean.txt", "hello"), status(rules=[]))
        self.assertEqual((r["verdict"], r["reason"]), ("BLOCK", "EXIT_POINT_BLOCKED"))

    def test_monitor_without_rules_logs_everything(self):
        r = ci.inspect_file(self.write("clean.txt", "hello"), status("REPORT_ONLY", rules=[]))
        self.assertEqual((r["verdict"], r["reason"]), ("LOG", "EXIT_POINT_MONITORED"))

    def test_sql_by_extension(self):
        r = ci.inspect_file(self.write("db.sql", "SELECT 1;"), status(file_types=BLOCK_SQL_EXE))
        self.assertEqual(r["reason"], "FILE_TYPE_BLOCKED")

    def test_sql_dump_renamed_to_txt(self):
        dump = "CREATE TABLE kh (id int);\nINSERT INTO kh VALUES (1);\nINSERT INTO kh VALUES (2);\n"
        r = ci.inspect_file(self.write("ghi_chu.txt", dump), status(file_types=BLOCK_SQL_EXE))
        self.assertEqual((r["real_type"], r["reason"]), ("sql", "FILE_TYPE_BLOCKED"))

    def test_exe_renamed_to_txt(self):
        r = ci.inspect_file(self.write("readme.txt", ms.FAKE_EXE), status(file_types=BLOCK_SQL_EXE))
        self.assertEqual((r["real_type"], r["reason"]), ("exe", "FILE_TYPE_BLOCKED"))
        self.assertTrue(r["extension_mismatch"])

    def test_xlsx_renamed_to_jpg(self):
        rows = [["CCCD", CCCD_OK]]
        r = ci.inspect_file(self.write("anh.jpg", ms.build_xlsx(rows)), status())
        self.assertEqual(r["real_type"], "xlsx")
        self.assertTrue(r["extension_mismatch"])
        self.assertEqual(r["confidence_level"], "CRITICAL")  # HIGH + đổi đuôi

    def test_legit_alias_extension_not_mismatch(self):
        r = ci.inspect_file(self.write("macro.xlsm", ms.build_xlsx([["a"]])), status())
        self.assertFalse(r["extension_mismatch"])

    def test_zip_content_scanned(self):
        z = ms.build_zip({"in/kh.txt": "CCCD " + CCCD_OK})
        r = ci.inspect_file(self.write("gon.zip", z), status())
        self.assertEqual((r["verdict"], r["reason"]), ("BLOCK", "CONTENT_MATCH"))

    def test_zip_hiding_sql(self):
        z = ms.build_zip({"backup.sql": "CREATE TABLE a(i int);"})
        r = ci.inspect_file(self.write("gon.zip", z), status(file_types=BLOCK_SQL_EXE))
        self.assertEqual(r["reason"], "FILE_TYPE_BLOCKED")

    def test_encrypted_zip(self):
        z = ms.mark_zip_encrypted(ms.build_zip({"a.txt": "secret"}))
        r = ci.inspect_file(self.write("pass.zip", z), status())
        self.assertEqual((r["verdict"], r["reason"]), ("BLOCK", "ENCRYPTED_CONTENT"))

    def test_utf16_text(self):
        r = ci.inspect_file(self.write("u16.txt", ("CCCD: " + CCCD_OK).encode("utf-16")), status())
        self.assertIn("PII_CCCD", r["matched_rule_names"])

    def test_exception_allowed_file(self):
        p = self.write("mau_bieu.txt", "CCCD " + CCCD_OK)
        r = ci.inspect_file(p, status(allowed_files=["mau_bieu.txt"], allowed_locations=[]))
        self.assertEqual((r["verdict"], r["reason"]), ("ALLOW", "ALLOWED_FILE"))

    def test_exception_allowed_location(self):
        p = self.write("x.txt", "CCCD " + CCCD_OK)
        r = ci.inspect_file(p, status(allowed_files=[], allowed_locations=[self.dir]))
        self.assertEqual(r["reason"], "ALLOWED_LOCATION")

    def test_missing_file_fails_closed(self):
        r = ci.inspect_file(os.path.join(self.dir, "khong_ton_tai.docx"), status())
        self.assertEqual((r["verdict"], r["reason"]), ("BLOCK", "UNREADABLE"))

    def test_hash_and_log_format(self):
        r = ci.inspect_file(self.write("x.txt", "CCCD " + CCCD_OK), status())
        self.assertEqual(len(r["file_hash_sha256"]), 64)
        log = ci.to_log_inspection(r)
        self.assertNotIn(CCCD_OK, str(log))  # log không chứa dữ liệu thật
        self.assertEqual(ci.to_report_fields(r)["confidence_score"], "HIGH")

    @unittest.skipUnless(HAS_PDF, "chua cai pypdf")
    def test_pdf(self):
        p = self.write("the.pdf", ms.build_pdf(["Card number: " + CARD_OK]))
        r = ci.inspect_file(p, status())
        self.assertIn("FINANCE_CREDIT_CARD", r["matched_rule_names"])

    def test_performance_5mb_text_under_1s(self):
        people = ms.fake_people(200)
        line = " ".join("%s %s %s" % (p["cccd"], p["phone"], p["email"]) for p in people) + "\n"
        data = (line * (5 * 1024 * 1024 // len(line) + 1)).encode("utf-8")[:5 * 1024 * 1024]
        p = self.write("big.csv", data)
        t0 = time.perf_counter()
        r = ci.inspect_file(p, status())
        elapsed = time.perf_counter() - t0
        print("\n    [perf] file 5MB: %.0f ms" % (elapsed * 1000))
        self.assertEqual(r["verdict"], "BLOCK")
        self.assertLess(elapsed, 3.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
