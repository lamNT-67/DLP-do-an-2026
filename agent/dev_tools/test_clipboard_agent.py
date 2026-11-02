"""
Test phần LOGIC của clipboard_agent (không cần Windows, không cần clipboard thật).
Phần gọi Win32 API thì test bằng tay theo hướng dẫn trong docs.

    cd agent
    python -m unittest dev_tools.test_clipboard_agent -v
"""

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import clipboard_agent as ca  # noqa: E402
import make_samples as ms  # noqa: E402

CCCD = "001203012345"


def policies(action="BLOCK", exit_points=("CLIPBOARD", "SCREEN_CAPTURE"), rules=None):
    return [{"policy_id": 7, "action": action, "exit_points": list(exit_points),
             "content_rules": ca.DEFAULT_RULES if rules is None else rules,
             "file_types": ca.DEFAULT_FILE_TYPES, "allowed_files": [], "allowed_locations": []}]


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="dlp_clip_")
        self.logdir = os.path.join(self.dir, "logs")
        patcher = mock.patch.object(ca, "write_log_event", side_effect=self._capture_log)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.logs, self.reports = [], []

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _capture_log(self, *args):
        self.logs.append(args)

    def guard(self, pols):
        g = ca.ClipboardGuard("PC-TEST", lambda: pols, self.reports.append)
        return g

    def wait_reports(self, n):
        import time
        for _ in range(50):
            if len(self.reports) >= n:
                return
            time.sleep(0.02)


class TestText(Base):
    def test_sensitive_text_blocked_and_notice_hides_data(self):
        block, notice = self.guard(policies()).on_text("So CCCD cua khach: " + CCCD, "excel.exe")
        self.assertTrue(block)
        self.assertIn("PII_CCCD", notice)
        self.assertNotIn(CCCD, notice)
        self.assertNotIn(CCCD, json.dumps(self.logs, ensure_ascii=False, default=str))  # log đã che

    def test_report_sent_with_rule_and_level(self):
        self.guard(policies()).on_text("CCCD " + CCCD, "notepad.exe")
        self.wait_reports(1)
        r = self.reports[0]
        self.assertEqual((r["exit_point_type"], r["action_taken"], r["process_name"]),
                         ("CLIPBOARD", "BLOCKED_DELETE", "notepad.exe"))
        self.assertEqual(r["confidence_score"], "HIGH")

    def test_clean_text_allowed_no_log(self):
        block, _ = self.guard(policies()).on_text("Hop luc 3h chieu nhe", "zalo.exe")
        self.assertFalse(block)
        self.assertEqual(self.logs, [])

    def test_single_email_only_logged(self):
        block, _ = self.guard(policies()).on_text("gui qua a@example.com nhe")
        self.assertFalse(block)
        self.assertEqual(self.logs[0][8], "LOGGED")

    def test_monitor_mode_never_blocks(self):
        block, _ = self.guard(policies("REPORT_ONLY")).on_text("CCCD " + CCCD)
        self.assertFalse(block)
        self.assertEqual(self.logs[0][8], "LOGGED")

    def test_not_governed(self):
        block, _ = self.guard(policies(exit_points=("USB",))).on_text("CCCD " + CCCD)
        self.assertFalse(block)
        self.assertEqual(self.logs, [])

    def test_block_without_rules_blocks_any_copy(self):
        block, _ = self.guard(policies(rules=[])).on_text("hello")
        self.assertTrue(block)


class TestFilesAndImages(Base):
    def write(self, name, data):
        p = os.path.join(self.dir, name)
        with open(p, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode("utf-8"))
        return p

    def test_copy_sensitive_file_in_explorer_blocked(self):
        rows = [["CCCD"]] + [[p["cccd"]] for p in ms.fake_people(12)]
        bad = self.write("kh.xlsx", ms.build_xlsx(rows))
        ok = self.write("ok.txt", "bao cao tuan")
        block, notice = self.guard(policies()).on_files([ok, bad], "explorer.exe")
        self.assertTrue(block)
        self.assertIn("kh.xlsx", notice)

    def test_copy_clean_files_allowed(self):
        ok = self.write("ok.txt", "bao cao tuan")
        block, _ = self.guard(policies()).on_files([ok, self.dir], "explorer.exe")  # thư mục bị bỏ qua
        self.assertFalse(block)

    def test_screenshot_image_blocked(self):
        block, notice = self.guard(policies()).on_image("SnippingTool.exe")
        self.assertTrue(block)
        self.assertEqual(notice, ca.NOTICE_IMAGE)
        self.assertEqual(self.logs[0][2], "SCREEN_CAPTURE")

    def test_image_allowed_when_only_clipboard_governed(self):
        block, _ = self.guard(policies(exit_points=("CLIPBOARD",))).on_image()
        self.assertFalse(block)


class TestRouting(Base):
    """Cách phân loại nội dung clipboard (phần dễ sai nhất khi chạy thật)."""

    def data(self, text=None, image=False, files=None):
        return {"text": text, "image": image, "files": files or []}

    def test_excel_copy_with_image_and_clean_text_allowed(self):
        block, _ = ca.route_clipboard(self.guard(policies()), self.data("Ho ten\tSo luong", True), "EXCEL.EXE")
        self.assertFalse(block)

    def test_excel_copy_with_cccd_blocked_as_text(self):
        block, notice = ca.route_clipboard(self.guard(policies()), self.data("CCCD\t" + CCCD, True), "EXCEL.EXE")
        self.assertTrue(block)
        self.assertIn("PII_CCCD", notice)
        self.assertEqual(self.logs[-1][2], "CLIPBOARD")

    def test_printscreen_image_only_is_screenshot(self):
        block, notice = ca.route_clipboard(self.guard(policies()), self.data(None, True), None)
        self.assertTrue(block)
        self.assertEqual(notice, ca.NOTICE_IMAGE)

    def test_snipping_tool_owner_always_screenshot(self):
        self.assertTrue(ca.is_screenshot(self.data("x", True), "SnippingTool.exe"))

    def test_empty_clipboard_ignored(self):
        self.assertEqual(ca.route_clipboard(self.guard(policies()), self.data(), None), (False, None))


class TestScreenshotFolder(Base):
    def test_new_screenshot_file_deleted_old_kept(self):
        shots = Path(self.dir) / "Screenshots"
        shots.mkdir()
        old = shots / "cu.png"
        old.write_bytes(b"\x89PNG old")
        g = self.guard(policies())
        with mock.patch.object(ca, "screenshot_folders", return_value=[shots]), \
                mock.patch.object(ca.psutil, "process_iter", return_value=[]):
            g.tick()                                   # lần đầu: chỉ ghi nhớ file cũ
            new = shots / "Screenshot 2026-11-02.png"
            new.write_bytes(b"\x89PNG new")
            g.tick()
        self.assertTrue(old.exists())
        self.assertFalse(new.exists())
        self.assertEqual(self.logs[-1][8], "BLOCKED_DELETE")

    def test_monitor_mode_keeps_screenshot_file(self):
        shots = Path(self.dir) / "Screenshots"
        shots.mkdir()
        g = self.guard(policies("REPORT_ONLY"))
        with mock.patch.object(ca, "screenshot_folders", return_value=[shots]):
            g.tick()
            new = shots / "a.png"
            new.write_bytes(b"x")
            g.tick()
        self.assertTrue(new.exists())
        self.assertEqual(self.logs[-1][8], "LOGGED")

    def test_screenshot_tool_terminated_once_logged(self):
        proc = mock.Mock(pid=4321, info={"pid": 4321, "name": "SnippingTool.exe"})
        g = self.guard(policies())
        with mock.patch.object(ca, "screenshot_folders", return_value=[]), \
                mock.patch.object(ca.psutil, "process_iter", return_value=[proc]):
            g.tick()
            g.tick()
        self.assertEqual(proc.terminate.call_count, 2)
        kills = [l for l in self.logs if l[8] == "BLOCKED_KILL"]
        self.assertEqual(len(kills), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
