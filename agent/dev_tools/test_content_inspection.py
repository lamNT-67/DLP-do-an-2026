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
from unittest.mock import patch

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


class TestInspectionCoverage(Base):
    def check(self, result, verdict, reason, coverage, read, extract, scan):
        self.assertEqual((result["verdict"], result["reason"], result["inspection_coverage"]),
                         (verdict, reason, coverage))
        self.assertEqual(result["inspection_stages"], {"read": read, "extract": extract, "scan": scan})
        self.assertEqual(result["inspected"], scan != "NOT_RUN")
        log = ci.to_log_inspection(result)
        self.assertEqual(log["inspection_coverage"], coverage)
        self.assertEqual(log["inspection_stages"], result["inspection_stages"])

    def test_empty_and_exact_limits_are_full(self):
        with patch.multiple(ci, MAX_TEXT_READ_BYTES=4, MAX_TEXT_CHARS=4, MAX_FILE_BYTES=4):
            for text in ("", "abcd"):
                with self.subTest(text=text):
                    r = ci.inspect_file(self.write("sample.txt", text), status())
                    self.check(r, "ALLOW", "CLEAN", "FULL", "FULL", "FULL", "FULL")
                    self.assertIsNone(ci.to_report_fields(r)["confidence_score"])

    def test_limits_are_attributed_to_the_stage_that_stopped(self):
        path = self.write("sample.txt", "abcd")
        cases = [
            ({"MAX_FILE_BYTES": 3, "MAX_TEXT_READ_BYTES": 2}, ("PARTIAL", "FULL", "FULL")),
            ({"MAX_TEXT_READ_BYTES": 3}, ("FULL", "PARTIAL", "FULL")),
            ({"MAX_TEXT_CHARS": 3}, ("FULL", "FULL", "PARTIAL")),
        ]
        for limits, stages in cases:
            with self.subTest(limits=limits), patch.multiple(ci, **limits):
                r = ci.inspect_file(path, status())
                self.check(r, "ALLOW", "INSPECTION_INCOMPLETE", "PARTIAL", *stages)
                self.assertIsNone(ci.to_report_fields(r)["confidence_score"])

    def test_partial_scan_retains_match_and_action(self):
        path = self.write("sample.txt", "blue blue blue")
        for kind in ("REGEX", "DICTIONARY"):
            rule = {"id": 37, "rule_name": "COLOR", "rule_type": kind,
                    "pattern": "blue", "severity": "CRITICAL"}
            for action, verdict in (("BLOCK", "BLOCK"), ("REPORT_ONLY", "LOG")):
                with self.subTest(kind=kind, action=action), patch.object(ci, "MAX_MATCHES_PER_RULE", 2):
                    r = ci.inspect_file(path, status(action, rules=[rule]))
                    self.check(r, verdict, "CONTENT_MATCH", "PARTIAL", "FULL", "FULL", "PARTIAL")
                    self.assertEqual((r["matched_rule_ids"], r["match_count"]), ([37], 2))

    def test_skipped_rule_is_scan_error(self):
        rule = {"id": 1, "pattern": "("}
        for text in ("blue", ""):
            with self.subTest(text=text):
                r = ci.inspect_file(self.write("sample.txt", text), status(rules=[rule]))
                self.check(r, "ALLOW", "INSPECTION_INCOMPLETE", "ERROR", "FULL", "FULL", "ERROR")
        # An empty-matching regex still produces no hit on an empty input.
        self.assertEqual(ci.scan_text("", [{"id": 2, "pattern": "^$"}])["matched_rule_ids"], [])
        with patch.object(ci, "MAX_TEXT_CHARS", 2):
            r = ci.scan_content_with_rules("blue", [rule, {"id": 2, "pattern": "bl"}])
            self.assertEqual((r["inspection_coverage"], r["matched_rule_ids"]), ("ERROR", [2]))

    def test_read_failure_and_policy_shortcuts(self):
        path = os.path.join(self.dir, "absent.txt")
        self.check(ci.inspect_file(path, status()), "BLOCK", "UNREADABLE", "ERROR",
                   "ERROR", "NOT_RUN", "NOT_RUN")
        self.check(ci.inspect_file(path, status(allowed_files=["absent.txt"])), "ALLOW", "ALLOWED_FILE",
                   "PARTIAL", "NOT_RUN", "NOT_RUN", "NOT_RUN")
        path = self.write("sample.txt", "blue")
        self.check(ci.inspect_file(path, status(rules=[])), "BLOCK", "EXIT_POINT_BLOCKED",
                   "PARTIAL", "FULL", "NOT_RUN", "NOT_RUN")

    def test_extractor_coverage(self):
        image = b"GIF89a"
        cases = [
            ("image.gif", image, "ALLOW", "NOT_INSPECTABLE", "UNSUPPORTED", "NOT_RUN"),
            ("broken.zip", b"PK\x03\x04", "ALLOW", "NOT_INSPECTABLE", "ERROR", "NOT_RUN"),
            ("password.zip", ms.mark_zip_encrypted(ms.build_zip({"a.txt": "blue"})),
             "BLOCK", "ENCRYPTED_CONTENT", "UNSUPPORTED", "NOT_RUN"),
            ("mixed.zip", ms.build_zip({"a.txt": "blue", "b.gif": image}),
             "ALLOW", "INSPECTION_INCOMPLETE", "PARTIAL", "FULL"),
            ("binary.bin", b"\0blue", "ALLOW", "INSPECTION_INCOMPLETE", "PARTIAL", "FULL"),
            ("lossy.txt", b"blue\xff", "ALLOW", "INSPECTION_INCOMPLETE", "PARTIAL", "FULL"),
            ("ok.zip", ms.build_zip({"a.txt": "blue"}), "ALLOW", "CLEAN", "FULL", "FULL"),
            ("ok.docx", ms.build_docx(["blue"]), "ALLOW", "CLEAN", "FULL", "FULL"),
            ("ok.xlsx", ms.build_xlsx([["blue"]]), "ALLOW", "CLEAN", "FULL", "FULL"),
        ]
        for name, data, verdict, reason, extract, scan in cases:
            with self.subTest(name=name):
                r = ci.inspect_file(self.write(name, data), status())
                self.check(r, verdict, reason, extract, "FULL", extract, scan)

    def test_archive_budgets_propagate_to_file_coverage(self):
        path = self.write("samples.zip", ms.build_zip({"a.txt": "green", "b.txt": "blue"}))
        for limits in ({"MAX_ARCHIVE_MEMBERS": 1}, {"MAX_ZIP_MEMBER_BYTES": 4}, {"MAX_TEXT_READ_BYTES": 4}):
            with self.subTest(limits=limits), patch.multiple(ci, **limits):
                r = ci.inspect_file(path, status())
                self.check(r, "ALLOW", "INSPECTION_INCOMPLETE", "PARTIAL", "FULL", "PARTIAL", "FULL")

    @unittest.skipUnless(HAS_PDF, "chua cai pypdf")
    def test_pdf_without_text_and_pdf_page_budget(self):
        for lines, extract, reason in (([], "UNSUPPORTED", "INSPECTION_INCOMPLETE"),
                                       (["blue"], "FULL", "CLEAN")):
            with self.subTest(lines=lines):
                path = self.write("sample.pdf", ms.build_pdf(lines))
                self.check(ci.inspect_file(path, status()), "ALLOW", reason, extract, "FULL", extract, "FULL")
        with patch.object(ci, "MAX_PDF_PAGES", 0):
            self.check(ci.inspect_file(path, status()), "ALLOW", "INSPECTION_INCOMPLETE", "PARTIAL",
                       "FULL", "PARTIAL", "FULL")


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
