"""
Test clipboard decisions and replacement with mocked Win32 APIs.

    cd agent
    python -m unittest dev_tools.test_clipboard_agent -v
"""

import json
import os
import shutil
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import clipboard_agent as ca  # noqa: E402
import log_writer  # noqa: E402
import make_samples as ms  # noqa: E402
from policy_client import PolicyClient  # noqa: E402

CCCD = "001203012345"


def policies(action="BLOCK", exit_points=("CLIPBOARD", "SCREEN_CAPTURE"), rules=None):
    return [{"policy_id": 7, "action": action, "exit_points": list(exit_points),
             "content_rules": ca.DEFAULT_RULES if rules is None else rules,
             "file_types": ca.DEFAULT_FILE_TYPES, "allowed_files": [], "allowed_locations": []}]


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="dlp_clip_")
        self.logs, self.reports = [], []
        self.log_metadata = []
        self.delivery = mock.Mock()
        self.say = mock.Mock()
        self.replace = mock.Mock(return_value=ca.CLIPBOARD_REPLACED)
        for patcher in (mock.patch.object(ca, "write_log_event", side_effect=self._capture_log),
                        mock.patch.object(ca, "write_clipboard_delivery_status", self.delivery),
                        mock.patch.object(ca.threading, "Thread", side_effect=self._inline_thread),
                        mock.patch.object(ca, "_say", self.say)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _capture_log(self, *args, **metadata):
        self.logs.append(args)
        self.log_metadata.append(metadata)

    @staticmethod
    def _inline_thread(*, target, args=(), daemon):
        return mock.Mock(start=lambda: target(*args))

    def _report(self, payload):
        self.reports.append(payload)
        return len(self.reports)

    def guard(self, pols):
        return ca.ClipboardGuard("PC-TEST", lambda: pols, self._report)


class TestText(Base):
    def test_sensitive_text_blocked_and_notice_hides_data(self):
        block, notice = self.guard(policies()).on_text("So CCCD cua khach: " + CCCD, "excel.exe",
                                                       replace=self.replace)
        self.assertTrue(block)
        self.assertIn("PII_CCCD", notice)
        self.assertNotIn(CCCD, notice)
        self.assertNotIn(CCCD, json.dumps(self.logs, ensure_ascii=False, default=str))  # log đã che

    def test_report_sent_with_rule_and_level(self):
        self.guard(policies()).on_text("CCCD " + CCCD, "notepad.exe", replace=self.replace)
        r = self.reports[0]
        self.assertEqual((r["exit_point_type"], r["action_taken"], r["process_name"]),
                         ("CLIPBOARD", "BLOCKED_DELETE", "notepad.exe"))
        self.assertEqual(r["confidence_score"], "HIGH")
        self.assertTrue(r["username"])  # có gửi tên người dùng lên server

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
        block, _ = self.guard(policies(rules=[])).on_text("hello", replace=self.replace)
        self.assertTrue(block)

    def test_policy_verdict_alone_does_not_confirm_replacement(self):
        block, _ = self.guard(policies()).on_text("CCCD " + CCCD)
        self.assertTrue(block)
        self.assertEqual(self.reports[0]["action_taken"], "LOGGED")
        self.assertEqual(self.logs[0][7]["enforcement_result"], "UNCHANGED")
        self.assertEqual(self.logs[0][7]["enforcement_reason"], "NOT_ATTEMPTED")


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
        block, notice = self.guard(policies()).on_files([ok, bad], "explorer.exe", replace=self.replace)
        self.assertTrue(block)
        self.assertIn("kh.xlsx", notice)

    def test_copy_clean_files_allowed(self):
        ok = self.write("ok.txt", "bao cao tuan")
        block, _ = self.guard(policies()).on_files([ok, self.dir], "explorer.exe")  # thư mục bị bỏ qua
        self.assertFalse(block)

    def test_screenshot_image_blocked(self):
        block, notice = self.guard(policies()).on_image("SnippingTool.exe", replace=self.replace)
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
        block, notice = ca.route_clipboard(self.guard(policies()), self.data("CCCD\t" + CCCD, True), "EXCEL.EXE",
                                           replace=self.replace)
        self.assertTrue(block)
        self.assertIn("PII_CCCD", notice)
        self.assertEqual(self.logs[-1][2], "CLIPBOARD")

    def test_printscreen_image_only_is_screenshot(self):
        block, notice = ca.route_clipboard(self.guard(policies()), self.data(None, True), None,
                                           replace=self.replace)
        self.assertTrue(block)
        self.assertEqual(notice, ca.NOTICE_IMAGE)

    def test_snipping_tool_owner_always_screenshot(self):
        self.assertTrue(ca.is_screenshot(self.data("x", True), "SnippingTool.exe"))

    def test_empty_clipboard_ignored(self):
        self.assertEqual(ca.route_clipboard(self.guard(policies()), self.data(), None), (False, None))


class TestClipboardReplacement(Base):
    SEQUENCE = 100
    NOTICE_HANDLE = 200

    def setUp(self):
        super().setUp()
        # Bypass window creation, format registration, and the keyboard hook.
        self.watcher = ca.ClipboardWatcher.__new__(ca.ClipboardWatcher)
        self.watcher.guard = self.guard(policies())
        self.watcher.hwnd, self.watcher.cf_png = 10, 20
        self.watcher.trace_native_clipboard = False
        self.watcher.defer_clipboard_read = False
        self.watcher._pending_clipboard_read = None
        self.watcher._owner_name = mock.Mock(return_value="notepad.exe")
        self.user32 = self.watcher.user32 = mock.Mock()
        self.kernel32 = self.watcher.kernel32 = mock.Mock()
        self.ct = self.watcher.ct = mock.Mock()
        self.user32.GetClipboardOwner.return_value = 30
        self.user32.GetClipboardSequenceNumber.return_value = self.SEQUENCE
        self.user32.OpenClipboard.return_value = True
        self.user32.CloseClipboard.return_value = True
        self.user32.IsClipboardFormatAvailable.side_effect = {ca.CF_TEXT_UNICODE}.__contains__
        self.user32.GetClipboardData.return_value = 40
        self.user32.EmptyClipboard.return_value = True
        self.user32.SetClipboardData.return_value = self.NOTICE_HANDLE
        self.kernel32.GlobalAlloc.return_value = self.NOTICE_HANDLE
        self.kernel32.GlobalSize.return_value = 64
        self.kernel32.GlobalLock.return_value = 50
        self.kernel32.GlobalUnlock.return_value = False  # Zero locks remaining.
        self.ct.get_last_error.return_value = 0
        self.ct.wstring_at.return_value = "CCCD " + CCCD + "\0"

    def assert_block_failure(self, reason, state="UNCHANGED"):
        self.assertEqual([(r["policy_id"], r["action_taken"], r["enforcement_result"]) for r in self.reports],
                         [(7, "LOGGED", state)])
        self.assertEqual(len(self.logs), 1)
        log = self.logs[0]
        self.assertEqual((log[4], log[7]["verdict"], log[7]["enforcement_result"], log[7]["enforcement_reason"],
                          log[8], self.log_metadata[0]["policy_id"]),
                         ("BLOCK", "BLOCK", state, reason, "LOGGED", 7))
        self.assertNotIn("enforcement_reason", self.reports[0])

    def assert_no_clipboard_write(self):
        self.user32.EmptyClipboard.assert_not_called()
        self.user32.SetClipboardData.assert_not_called()

    def test_replacement_finishes_before_it_is_logged_or_reported(self):
        def set_notice(*_):
            self.assertEqual((self.logs, self.reports), ([], []))
            return self.NOTICE_HANDLE

        self.user32.SetClipboardData.side_effect = set_notice
        self.watcher._on_clipboard_update()

        self.assertEqual(self.user32.mock_calls[-8:], [
            mock.call.GetClipboardSequenceNumber(), mock.call.CloseClipboard(),
            mock.call.GetClipboardSequenceNumber(), mock.call.OpenClipboard(self.watcher.hwnd),
            mock.call.GetClipboardSequenceNumber(), mock.call.EmptyClipboard(),
            mock.call.SetClipboardData(ca.CF_TEXT_UNICODE, self.NOTICE_HANDLE), mock.call.CloseClipboard(),
        ])
        raw = (ca.NOTICE_TEXT.format(rules="PII_CCCD") + "\0").encode("utf-16-le")
        self.ct.memmove.assert_called_once_with(50, raw, len(raw))
        self.kernel32.GlobalFree.assert_not_called()
        report = self.reports[0]
        self.assertEqual((report["policy_id"], report["action_taken"], report["confidence_score"]),
                         (7, "BLOCKED_DELETE", "HIGH"))
        self.assertEqual(report["enforcement_result"], "REPLACED")
        self.assertTrue(report["matched_rule_ids"])
        self.assertEqual((self.logs[0][7]["enforcement_result"], self.logs[0][8], self.logs[0][9]),
                         ("REPLACED", "BLOCKED_DELETE", False))
        self.assertNotIn(CCCD, json.dumps(self.reports))

    def test_sequence_changed_before_enforcement_skips_replacement(self):
        self.user32.GetClipboardSequenceNumber.side_effect = [self.SEQUENCE, self.SEQUENCE + 1]
        self.watcher._on_clipboard_update()
        self.assert_block_failure("SEQUENCE_CHANGED")
        self.user32.OpenClipboard.assert_called_once_with(self.watcher.hwnd)  # Snapshot only.
        self.kernel32.GlobalAlloc.assert_not_called()
        self.assert_no_clipboard_write()

    def test_sequence_changed_while_opening_for_replacement(self):
        self.user32.OpenClipboard.side_effect = [True, False, True]
        self.user32.GetClipboardSequenceNumber.side_effect = [self.SEQUENCE, self.SEQUENCE, self.SEQUENCE + 1]
        with mock.patch.object(ca.time, "sleep"):
            self.watcher._on_clipboard_update()
        self.assert_block_failure("SEQUENCE_CHANGED")
        self.assert_no_clipboard_write()
        self.assertEqual(self.user32.CloseClipboard.call_count, 2)
        self.kernel32.GlobalFree.assert_called_once_with(self.NOTICE_HANDLE)

    def test_delayed_rendering_sequence_is_captured_after_the_read(self):
        def render(_):
            self.user32.GetClipboardSequenceNumber.return_value += 1
            return 40

        self.user32.GetClipboardData.side_effect = render
        self.watcher._on_clipboard_update()
        self.assertEqual(self.reports[0]["action_taken"], "BLOCKED_DELETE")

    def send_clipboard_update(self, milliseconds):
        with mock.patch.object(ca.time, "monotonic_ns", return_value=milliseconds * 1_000_000):
            self.watcher._wndproc(self.watcher.hwnd, ca.WM_CLIPBOARDUPDATE, 0, 0)

    def fire_clipboard_timer(self, milliseconds):
        with mock.patch.object(ca.time, "monotonic_ns", return_value=milliseconds * 1_000_000):
            self.watcher._wndproc(self.watcher.hwnd, ca.WM_TIMER, ca.CLIPBOARD_READ_TIMER, 0)

    def test_default_update_reads_immediately(self):
        self.send_clipboard_update(0)
        self.user32.SetTimer.assert_not_called()
        self.assertEqual(self.reports[0]["action_taken"], "BLOCKED_DELETE")

    def test_deferred_read_uses_fresh_snapshot_and_ignores_stale_timer(self):
        self.watcher.defer_clipboard_read = True
        self.watcher.guard.tick = mock.Mock()
        self.send_clipboard_update(0)
        self.user32.SetTimer.assert_called_once_with(self.watcher.hwnd, ca.CLIPBOARD_READ_TIMER, 25, None)
        self.user32.GetClipboardSequenceNumber.return_value += 1
        self.ct.wstring_at.return_value = "ordinary text\0"
        self.send_clipboard_update(20)
        self.fire_clipboard_timer(25)
        self.watcher._wndproc(self.watcher.hwnd, ca.WM_TIMER, ca.SCREENSHOT_TIMER, 0)
        self.watcher.guard.tick.assert_called_once_with()
        self.user32.OpenClipboard.assert_not_called()
        self.fire_clipboard_timer(45)
        self.fire_clipboard_timer(46)
        self.user32.OpenClipboard.assert_called_once_with(self.watcher.hwnd)
        self.user32.KillTimer.assert_called_once_with(self.watcher.hwnd, ca.CLIPBOARD_READ_TIMER)
        self.assert_no_clipboard_write()
        self.assertEqual((self.logs, self.reports), ([], []))
        self.assertIn('"coalesced_notifications":1', self.say.call_args.args[0])
        self.assertIn('"observed_sequence_changes":1', self.say.call_args.args[0])

    def test_continuous_updates_dispatch_at_cap_without_waiting_for_timer(self):
        self.watcher.defer_clipboard_read = True
        for milliseconds in (0, 10, 20, 30, 40, 49):
            self.send_clipboard_update(milliseconds)
        self.user32.OpenClipboard.assert_not_called()
        self.fire_clipboard_timer(49)
        self.user32.OpenClipboard.assert_not_called()
        self.send_clipboard_update(50)
        self.assertEqual(self.reports[0]["action_taken"], "BLOCKED_DELETE")
        self.assertIn('"deferral_ms":50.0', self.say.call_args.args[0])
        self.assertIsNone(self.watcher._pending_clipboard_read)

    def test_timer_arm_failure_falls_back_and_is_observable(self):
        self.watcher.defer_clipboard_read = True
        self.user32.SetTimer.return_value = 0
        self.ct.get_last_error.return_value = 0
        self.send_clipboard_update(0)
        self.fire_clipboard_timer(25)
        self.assertEqual(len(self.reports), 1)
        self.assertEqual(self.reports[0]["action_taken"], "BLOCKED_DELETE")
        self.assertIn('"event":"timer_fallback"', self.say.call_args.args[0])

    def test_rearm_near_cap_keeps_deadline_inside_windows_timer_minimum(self):
        self.watcher.defer_clipboard_read = True
        for milliseconds in (0, 24, 45):
            self.send_clipboard_update(milliseconds)
        self.assertEqual(self.user32.SetTimer.call_count, 2)
        self.fire_clipboard_timer(49)
        self.assertEqual(self.reports[0]["action_taken"], "BLOCKED_DELETE")

    def test_deferred_rendering_uses_post_read_sequence_and_confirms_receipt(self):
        self.watcher.defer_clipboard_read = True

        def render(_):
            self.user32.GetClipboardSequenceNumber.return_value += 1
            return 40

        self.user32.GetClipboardData.side_effect = render
        self.send_clipboard_update(0)
        self.fire_clipboard_timer(25)
        self.assertEqual(self.reports[0]["action_taken"], "BLOCKED_DELETE")
        self.assertEqual(self.logs[0][8:], ("BLOCKED_DELETE", False))
        self.delivery.assert_called_once_with(
            self.log_metadata[0]["event_id"], "ACKNOWLEDGED", server_log_id=1)
        self.assertNotIn("observed_sequence_changes", str(self.say.call_args_list))

    def test_deferred_snapshot_cannot_replace_new_content_after_rendering(self):
        self.watcher.defer_clipboard_read = True
        self.user32.GetClipboardSequenceNumber.side_effect = [
            self.SEQUENCE, self.SEQUENCE, self.SEQUENCE + 1, self.SEQUENCE + 1, self.SEQUENCE + 2,
        ]
        self.send_clipboard_update(0)
        self.fire_clipboard_timer(25)
        self.assert_block_failure("SEQUENCE_CHANGED")
        self.assert_no_clipboard_write()

    def test_deferred_replacement_rejects_owner_change_at_same_sequence(self):
        self.watcher.defer_clipboard_read = True
        self.user32.GetClipboardOwner.side_effect = [30, 30, 31]
        self.send_clipboard_update(0)
        self.fire_clipboard_timer(25)
        self.assert_block_failure("OWNER_CHANGED")
        self.assert_no_clipboard_write()

    def test_deferred_read_discards_snapshot_if_owner_changes_during_rendering(self):
        self.watcher.defer_clipboard_read = True
        self.user32.GetClipboardOwner.side_effect = [30, 31]
        self.send_clipboard_update(0)
        self.fire_clipboard_timer(25)
        self.assertEqual((self.logs, self.reports), ([], []))
        self.assertIn("owner_changed_during_read", self.say.call_args.args[0])
        self.assert_no_clipboard_write()

    def test_deferred_unreadable_advertised_text_is_visible_without_policy_event(self):
        self.watcher.defer_clipboard_read = True
        self.user32.GetClipboardData.return_value = None
        self.send_clipboard_update(0)
        self.fire_clipboard_timer(25)
        self.user32.CloseClipboard.assert_called_once_with()
        self.assertIn('"event":"unreadable_advertised_formats","formats":[13]', self.say.call_args.args[0])
        self.assertEqual((self.logs, self.reports), ([], []))
        self.delivery.assert_not_called()
        self.assert_no_clipboard_write()

    def test_unreadable_text_does_not_turn_mixed_content_into_screenshot(self):
        self.watcher.defer_clipboard_read = True
        self.user32.IsClipboardFormatAvailable.side_effect = {ca.CF_DIB, ca.CF_TEXT_UNICODE}.__contains__
        self.user32.GetClipboardData.return_value = None
        self.send_clipboard_update(0)
        self.fire_clipboard_timer(25)
        self.assertEqual((self.logs, self.reports), ([], []))
        self.assertIn("unreadable_advertised_formats", self.say.call_args.args[0])
        self.assert_no_clipboard_write()

    def test_deferred_close_failure_never_claims_block(self):
        self.watcher.defer_clipboard_read = True
        self.user32.CloseClipboard.side_effect = [True, False]
        self.send_clipboard_update(0)
        self.fire_clipboard_timer(25)
        self.assert_block_failure("CLOSE_CLIPBOARD_FAILED", "UNCERTAIN")
        self.assertIn("CloseClipboard failed phase=replace", str(self.say.call_args_list))

    def test_unavailable_sequence_leaves_clipboard_untouched(self):
        self.user32.GetClipboardSequenceNumber.return_value = 0
        self.watcher._on_clipboard_update()
        self.assert_block_failure("SEQUENCE_UNAVAILABLE")
        self.assert_no_clipboard_write()

    def test_own_notice_is_skipped_and_external_content_is_inspected(self):
        self.user32.GetClipboardOwner.return_value = self.watcher.hwnd
        self.watcher._on_clipboard_update()
        self.assertEqual((self.logs, self.reports), ([], []))
        self.user32.GetClipboardData.assert_not_called()
        self.user32.CloseClipboard.assert_called_once_with()

        self.user32.GetClipboardOwner.return_value = 30
        self.user32.GetClipboardSequenceNumber.return_value += 1
        self.watcher._on_clipboard_update()
        self.assertEqual(self.reports[0]["action_taken"], "BLOCKED_DELETE")

    def test_failed_snapshot_close_does_not_dispatch_or_reopen(self):
        self.user32.CloseClipboard.return_value = False
        self.ct.get_last_error.return_value = 1418
        with mock.patch.object(ca, "route_clipboard") as route:
            self.watcher._on_clipboard_update()
        self.user32.OpenClipboard.assert_called_once_with(self.watcher.hwnd)
        self.user32.CloseClipboard.assert_called_once_with()
        route.assert_not_called()
        self.assert_no_clipboard_write()
        self.assertEqual((self.logs, self.reports), ([], []))
        self.say.assert_called_once_with("CloseClipboard failed phase=read winerror=1418")

    def test_failed_self_notice_close_is_visible(self):
        self.user32.GetClipboardOwner.return_value = self.watcher.hwnd
        self.user32.CloseClipboard.return_value = False
        self.ct.get_last_error.return_value = 1418
        self.watcher._on_clipboard_update()
        self.user32.GetClipboardData.assert_not_called()
        self.user32.CloseClipboard.assert_called_once_with()
        self.say.assert_called_once_with("CloseClipboard failed phase=read winerror=1418")

    def test_snapshot_exception_unlocks_memory_and_checks_close(self):
        self.ct.wstring_at.side_effect = ValueError("private clipboard data")
        self.user32.CloseClipboard.return_value = False
        self.ct.get_last_error.return_value = 1418
        with self.assertRaises(ValueError):
            self.watcher._on_clipboard_update()
        self.kernel32.GlobalUnlock.assert_called_once_with(40)
        self.user32.CloseClipboard.assert_called_once_with()
        self.assertEqual((self.logs, self.reports), ([], []))
        self.say.assert_called_once_with("CloseClipboard failed phase=read winerror=1418")

    def test_native_trace_times_data_fetch_and_emits_after_successful_close(self):
        self.watcher.trace_native_clipboard = True
        self.watcher.guard = self.guard(policies("REPORT_ONLY"))

        def check_released():
            self.say.assert_not_called()
            return True

        self.user32.CloseClipboard.side_effect = check_released
        ticks = [0, 2_000_000, 3_000_000, 1_103_000_000, 1_104_000_000]
        with mock.patch.object(ca.time, "perf_counter_ns", side_effect=ticks):
            self.watcher._on_clipboard_update()
        message = self.say.call_args_list[0].args[0]
        trace = json.loads(message.removeprefix("clipboard_native "))
        self.assertEqual((trace["phase"], trace["hwnd"], trace["owner_hwnd"]), ("read", "0xa", "0x1e"))
        self.assertTrue(trace["open_ok"])
        self.assertTrue(trace["close_ok"])
        self.assertEqual((trace["open_ms"], trace["hold_until_close_return_ms"]), (2, 1102))
        self.assertEqual(trace["get_data_ms"], {str(ca.CF_TEXT_UNICODE): 1100})
        self.assertNotIn(CCCD, message)
        self.assert_no_clipboard_write()

    def test_native_trace_preserves_failed_close_error_before_opener_sample(self):
        self.watcher.trace_native_clipboard = True
        self.user32.CloseClipboard.return_value = False
        self.user32.GetOpenClipboardWindow.return_value = self.watcher.hwnd

        def read_error():
            self.user32.CloseClipboard.assert_called_once_with()
            self.user32.GetOpenClipboardWindow.assert_not_called()
            return 1418

        self.ct.get_last_error.side_effect = read_error
        self.watcher._on_clipboard_update()
        trace = json.loads(self.say.call_args.args[0].removeprefix("clipboard_native "))
        self.assertFalse(trace["close_ok"])
        self.assertEqual((trace["close_error"], trace["opener_after_failed_close"]), (1418, "0xa"))
        self.assert_no_clipboard_write()

    def test_open_failure_leaves_clipboard_untouched(self):
        self.user32.OpenClipboard.side_effect = [True] + [False] * 10
        with mock.patch.object(ca.time, "sleep"):
            self.watcher._on_clipboard_update()
        self.assert_block_failure("OPEN_CLIPBOARD_FAILED")
        self.assert_no_clipboard_write()
        self.user32.CloseClipboard.assert_called_once_with()  # Only the snapshot was opened.
        self.kernel32.GlobalFree.assert_called_once_with(self.NOTICE_HANDLE)

    def test_open_failure_before_snapshot_cannot_produce_a_finding(self):
        self.user32.OpenClipboard.return_value = False
        with mock.patch.object(ca.time, "sleep"):
            self.watcher._on_clipboard_update()
        self.assertEqual((self.logs, self.reports), ([], []))
        self.user32.CloseClipboard.assert_not_called()
        self.assert_no_clipboard_write()

    def test_empty_failure_never_sets_notice(self):
        self.user32.EmptyClipboard.return_value = False
        self.watcher._on_clipboard_update()
        self.assert_block_failure("EMPTY_CLIPBOARD_FAILED")
        self.user32.EmptyClipboard.assert_called_once_with()
        self.user32.SetClipboardData.assert_not_called()
        self.assertEqual(self.user32.CloseClipboard.call_count, 2)
        self.kernel32.GlobalFree.assert_called_once_with(self.NOTICE_HANDLE)

    def test_empty_failure_with_changed_sequence_is_uncertain(self):
        def fail_empty():
            self.user32.GetClipboardSequenceNumber.return_value += 1
            return False

        self.user32.EmptyClipboard.side_effect = fail_empty
        self.watcher._on_clipboard_update()
        self.assert_block_failure("EMPTY_CLIPBOARD_FAILED", "UNCERTAIN")
        self.user32.SetClipboardData.assert_not_called()

    def test_allocation_failure_leaves_clipboard_untouched(self):
        self.kernel32.GlobalAlloc.return_value = None
        self.watcher._on_clipboard_update()
        self.assert_block_failure("GLOBAL_ALLOC_FAILED")
        self.assert_no_clipboard_write()
        self.kernel32.GlobalFree.assert_not_called()

    def test_notice_lock_failure_frees_allocation(self):
        self.kernel32.GlobalLock.side_effect = [50, None]
        self.watcher._on_clipboard_update()
        self.assert_block_failure("GLOBAL_LOCK_FAILED")
        self.assert_no_clipboard_write()
        self.kernel32.GlobalFree.assert_called_once_with(self.NOTICE_HANDLE)

    def test_notice_unlock_failure_leaves_clipboard_untouched(self):
        self.ct.get_last_error.return_value = 158
        self.watcher._on_clipboard_update()
        self.assert_block_failure("GLOBAL_UNLOCK_FAILED")
        self.assert_no_clipboard_write()
        self.kernel32.GlobalFree.assert_called_once_with(self.NOTICE_HANDLE)

    def test_notice_write_failure_unlocks_and_frees_allocation(self):
        self.ct.memmove.side_effect = OSError("private data in write exception")
        self.watcher._on_clipboard_update()
        self.assert_block_failure("NOTICE_WRITE_FAILED")
        self.assert_no_clipboard_write()
        self.kernel32.GlobalUnlock.assert_called_with(self.NOTICE_HANDLE)
        self.kernel32.GlobalFree.assert_called_once_with(self.NOTICE_HANDLE)
        self.assertNotIn("private data", str(self.say.call_args_list))

    def test_image_set_data_failure_reports_logged_after_emptying(self):
        self.user32.IsClipboardFormatAvailable.side_effect = {ca.CF_DIB}.__contains__
        self.user32.SetClipboardData.return_value = None
        self.watcher._on_clipboard_update()
        self.assert_block_failure("SET_CLIPBOARD_DATA_FAILED", "CLEARED_WITHOUT_NOTICE")
        self.assertEqual(self.reports[0]["exit_point_type"], "SCREEN_CAPTURE")
        self.user32.EmptyClipboard.assert_called_once_with()
        self.user32.SetClipboardData.assert_called_once_with(ca.CF_TEXT_UNICODE, self.NOTICE_HANDLE)
        self.assertEqual(self.user32.CloseClipboard.call_count, 2)
        self.kernel32.GlobalFree.assert_called_once_with(self.NOTICE_HANDLE)

    def test_failed_close_after_set_data_does_not_free_system_owned_handle(self):
        self.user32.CloseClipboard.side_effect = [True, False]
        self.watcher._on_clipboard_update()
        self.assert_block_failure("CLOSE_CLIPBOARD_FAILED", "UNCERTAIN")
        self.kernel32.GlobalFree.assert_not_called()

    def test_interrupted_notice_installation_records_an_uncertain_state(self):
        self.user32.SetClipboardData.side_effect = OSError("private notice data")
        self.watcher._on_clipboard_update()
        self.assert_block_failure("REPLACEMENT_ERROR", "UNCERTAIN")
        self.user32.EmptyClipboard.assert_called_once_with()
        self.assertEqual(self.user32.CloseClipboard.call_count, 2)
        self.kernel32.GlobalFree.assert_called_once_with(self.NOTICE_HANDLE)
        self.assertNotIn("private notice data", str(self.say.call_args_list))

    def test_report_only_reads_text_and_images_without_replacing(self):
        self.watcher.guard = self.guard(policies("REPORT_ONLY"))
        self.watcher._on_clipboard_update()
        self.user32.IsClipboardFormatAvailable.side_effect = {ca.CF_DIB}.__contains__
        self.watcher._on_clipboard_update()

        self.assert_no_clipboard_write()
        self.kernel32.GlobalAlloc.assert_not_called()
        self.assertEqual([(r["exit_point_type"], r["policy_id"], r["action_taken"]) for r in self.reports],
                         [("CLIPBOARD", 7, "LOGGED"), ("SCREEN_CAPTURE", 7, "LOGGED")])
        self.assertTrue(all("enforcement_result" not in log[7] for log in self.logs))
        self.assertTrue(all("enforcement_result" not in report for report in self.reports))

    def test_file_copy_replaces_once_and_keeps_each_files_policy(self):
        folder = Path(self.dir)
        files = [folder / name for name in ("first.txt", "second.txt", "monitor.txt")]
        for path, content in zip(files, ("CCCD " + CCCD, "CCCD " + CCCD, "MONITOR")):
            path.write_text(content, encoding="utf-8")
        rule = {"id": 91, "rule_name": "Monitor", "rule_type": "REGEX", "pattern": "MONITOR",
                "severity": "HIGH", "category": "INTERNAL_DOC"}
        monitors = policies("REPORT_ONLY", rules=[rule])
        monitors[0]["policy_id"] = 1
        self.watcher.guard = self.guard(monitors + policies())
        data = {"text": None, "files": [str(path) for path in files], "image": False}
        with mock.patch.object(self.watcher, "_read", return_value=(data, 30, self.SEQUENCE)):
            self.watcher._on_clipboard_update()

        self.user32.EmptyClipboard.assert_called_once_with()
        self.user32.SetClipboardData.assert_called_once_with(ca.CF_TEXT_UNICODE, self.NOTICE_HANDLE)
        self.assertEqual([(r["file_path"], r["policy_id"], r["action_taken"]) for r in self.reports],
                         [(str(files[0]), 7, "BLOCKED_DELETE"), (str(files[1]), 7, "BLOCKED_DELETE"),
                          (str(files[2]), 1, "LOGGED")])
        self.assertEqual(self.reports[2]["matched_rule_ids"], [91])
        self.assertEqual([r.get("enforcement_result") for r in self.reports], ["REPLACED", "REPLACED", None])


class TestPolicySummary(unittest.TestCase):
    def test_no_policy_warns_clearly(self):
        self.assertIn("CHUA CO POLICY", ca.policy_summary([]))
        self.assertIn("CHUA CO POLICY", ca.policy_summary(policies(exit_points=("USB",))))

    def test_summary_lists_each_channel(self):
        s = ca.policy_summary(policies())
        self.assertIn("CLIPBOARD = BLOCK (5 rule)", s)
        self.assertIn("SCREEN_CAPTURE = BLOCK", s)
        s = ca.policy_summary(policies("REPORT_ONLY", exit_points=("CLIPBOARD",)))
        self.assertIn("CLIPBOARD = REPORT_ONLY", s)
        self.assertIn("SCREEN_CAPTURE = khong ap dung", s)


class TestReporting(Base):
    def assert_delivery(self, status, server_log_id=None):
        self.delivery.assert_called_with(self.log_metadata[-1]["event_id"], status, server_log_id=server_log_id)

    def test_event_is_synced_before_worker_starts_and_receipt_uses_separate_file(self):
        event_path = Path(self.dir) / "dlp_events.log"
        delivery_path = Path(self.dir) / "clipboard_delivery.log"
        guard = self.guard(policies("REPORT_ONLY"))
        with (
            mock.patch.multiple(log_writer, LOG_FILE=event_path, CLIPBOARD_DELIVERY_FILE=delivery_path),
            mock.patch.object(ca, "write_log_event", wraps=log_writer.write_log_event),
            mock.patch.object(ca, "write_clipboard_delivery_status", wraps=log_writer.write_clipboard_delivery_status),
            mock.patch.object(ca.threading, "Thread") as thread,
            mock.patch.object(log_writer.os, "fsync", wraps=os.fsync) as sync,
        ):
            def check_local_record():
                self.assertTrue(event_path.is_file())
                self.assertFalse(delivery_path.exists())
                sync.assert_called_once()

            thread.return_value.start.side_effect = check_local_record
            guard.on_text("CCCD " + CCCD)
            thread.return_value.start.assert_called_once_with()
            original = event_path.read_bytes()
            event = json.loads(original)
            self.assertEqual((event["policy_id"], event["action_taken"]), (7, "LOGGED"))
            self.assertIs(event["reported_to_server"], False)
            self.assertIs(event["report_configured"], True)
            self.assertEqual(self.reports, [])

            thread.call_args.kwargs["target"]()
        self.assertEqual(len(self.reports), 1)
        self.assertEqual(event_path.read_bytes(), original)
        receipt = json.loads(delivery_path.read_bytes())
        self.assertEqual(receipt["event_id"], event["event_id"])
        self.assertEqual((receipt["status"], receipt["server_log_id"]), ("ACKNOWLEDGED", 1))
        self.assertIs(receipt["reported_to_server"], True)
        self.assertNotIn("action_taken", receipt)
        self.assertNotIn(CCCD.encode(), delivery_path.read_bytes())
        self.assertEqual(sync.call_count, 2)

    def test_concurrent_pending_reports_correlate_out_of_order_receipts(self):
        guard = self.guard(policies("REPORT_ONLY"))
        with mock.patch.object(ca.threading, "Thread") as thread:
            guard.on_text("CCCD " + CCCD)
            guard.on_text("CCCD " + CCCD)

        first, second = [entry["event_id"] for entry in self.log_metadata]
        self.assertNotEqual(first, second)
        self.delivery.assert_not_called()
        for worker in reversed(thread.call_args_list):
            worker.kwargs["target"]()
        self.assertEqual(self.delivery.call_args_list, [
            mock.call(second, "ACKNOWLEDGED", server_log_id=1),
            mock.call(first, "ACKNOWLEDGED", server_log_id=2),
        ])
        self.assertEqual(len(self.logs), 2)
        self.assertTrue(all(log[9] is False for log in self.logs))

    def test_demo_persists_evidence_without_delivery_status(self):
        guard = ca.ClipboardGuard("PC-TEST", lambda: policies("REPORT_ONLY"))
        guard.on_text("CCCD " + CCCD)
        self.assertEqual(self.logs[0][8:], ("LOGGED", False))
        self.assertIs(self.log_metadata[0]["report_configured"], False)
        self.assertIs(self.log_metadata[0]["durable"], True)
        self.delivery.assert_not_called()

    def test_thread_start_failure_records_no_acknowledgment(self):
        guard = self.guard(policies("REPORT_ONLY"))
        with mock.patch.object(ca.threading, "Thread") as thread:
            thread.return_value.start.side_effect = RuntimeError("cannot start thread")
            guard.on_text("CCCD " + CCCD)
        self.assertEqual(self.reports, [])
        self.assertIs(self.logs[0][9], False)
        self.assert_delivery("NOT_STARTED")

    def test_reporter_exception_is_not_acknowledged_or_logged_verbatim(self):
        guard = self.guard(policies("REPORT_ONLY"))
        guard.reporter = mock.Mock(side_effect=RuntimeError("private report data"))
        guard.on_text("CCCD " + CCCD)
        self.assertIs(self.logs[0][9], False)
        self.assert_delivery("UNACKNOWLEDGED")
        self.assertNotIn("private report data", str(self.say.call_args_list))

    def test_local_event_write_failure_still_allows_delivery_without_orphan_status(self):
        guard = self.guard(policies())
        with mock.patch.object(ca, "write_log_event", side_effect=OSError("private directory")):
            guard.on_text("CCCD " + CCCD, replace=self.replace)
        self.assertEqual(self.reports[0]["action_taken"], "BLOCKED_DELETE")
        self.delivery.assert_not_called()
        self.assertNotIn("private directory", str(self.say.call_args_list))

    def test_delivery_status_write_failure_keeps_local_evidence(self):
        self.delivery.side_effect = OSError("private directory")
        guard = self.guard(policies())
        guard.on_text("CCCD " + CCCD, replace=self.replace)
        self.assertEqual(len(self.logs), 1)
        self.assertEqual(self.logs[0][8:], ("BLOCKED_DELETE", False))
        self.assert_delivery("ACKNOWLEDGED", 1)
        self.assertNotIn("private directory", str(self.say.call_args_list))

    def test_server_policy_only_acknowledges_api_success_response(self):
        server_policy = ca.ServerPolicy("unused.ini")
        server_policy.client = PolicyClient("https://dlp.example/api", "PC-TEST", "synthetic-token")
        guard = self.guard(policies("REPORT_ONLY"))
        guard.reporter = server_policy.report
        for code, body, server_log_id in (
            (201, b'{"status":"ok","id":12}', 12),
            (201, b'{"status":"ok"}', None),
            (201, b'{"status":"ok","id":true}', None),
            (201, b'{"status":"ok","id":0}', None),
            (201, b'{"status":"error","id":12}', None),
            (201, b'<html>login</html>', None),
            (200, b'{"status":"ok","id":12}', None),
            (400, b'{"error":"policy_id is not assigned"}', None),
        ):
            with self.subTest(code=code, body=body):
                response = requests.Response()
                response.status_code, response._content = code, body
                response.url = "https://dlp.example/api/agent_report.php"
                with mock.patch.object(requests, "post", return_value=response) as post:
                    guard.on_text("CCCD " + CCCD)
                payload = post.call_args.kwargs["json"]
                self.assertEqual((payload["policy_id"], payload["action_taken"]), (7, "LOGGED"))
                self.assertIs(self.logs[-1][9], False)
                status = "ACKNOWLEDGED" if server_log_id is not None else "UNACKNOWLEDGED"
                self.assert_delivery(status, server_log_id)

    def test_transport_failure_keeps_enforcement_result_and_hides_details(self):
        server_policy = ca.ServerPolicy("unused.ini")
        server_policy.client = PolicyClient("https://dlp.example/api", "PC-TEST", "synthetic-token")
        guard = self.guard(policies())
        guard.reporter = server_policy.report
        with mock.patch.object(requests, "post", side_effect=requests.Timeout("synthetic-token")), \
                mock.patch("builtins.print") as print_message:
            guard.on_text("CCCD " + CCCD, replace=self.replace)
        self.assertEqual(self.logs[0][8:], ("BLOCKED_DELETE", False))
        self.assert_delivery("UNACKNOWLEDGED")
        self.assertNotIn("synthetic-token", str(self.say.call_args_list))
        print_message.assert_not_called()


class TestLocalLogWrites(unittest.TestCase):
    def test_concurrent_appends_preserve_rows_in_each_jsonl_file(self):
        def write_both(event_id):
            log_writer.write_log_event("PC-TEST", "clipboard", "CLIPBOARD", "logged", "BLOCK",
                                       {}, {}, {}, "LOGGED", False, event_id=event_id, durable=True)
            log_writer.write_clipboard_delivery_status(event_id, "UNACKNOWLEDGED")

        with tempfile.TemporaryDirectory(prefix="dlp-local-log-") as directory:
            events_path = Path(directory) / "dlp_events.log"
            delivery_path = Path(directory) / "clipboard_delivery.log"
            event_ids = [str(index) for index in range(40)]
            with mock.patch.multiple(log_writer, LOG_FILE=events_path, CLIPBOARD_DELIVERY_FILE=delivery_path):
                with ThreadPoolExecutor(max_workers=4) as pool:
                    list(pool.map(write_both, event_ids))

            for path in (events_path, delivery_path):
                events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
                self.assertCountEqual([event["event_id"] for event in events], event_ids)
                self.assertTrue(all(event["reported_to_server"] is False for event in events))


class TestHotkeys(Base):
    """Lớp chặn từ phím bấm: mô phỏng chuỗi sự kiện bàn phím như Windows gửi vào hook."""

    DOWN, UP = ca.WM_KEYDOWN, ca.WM_KEYUP

    def press(self, f, *vks):
        """Nhấn lần lượt các phím rồi nhả theo thứ tự ngược lại. Trả về kết quả của từng sự kiện."""
        out = [(vk, "down") + f.on_key(vk, self.DOWN) for vk in vks]
        out += [(vk, "up") + f.on_key(vk, self.UP) for vk in reversed(vks)]
        return {(vk, kind): (swallow, mask) for vk, kind, swallow, mask in out}

    def flt(self, pols):
        return ca.HotkeyFilter(self.guard(pols).on_screenshot_hotkey)

    def test_printscreen_swallowed_down_and_up(self):
        r = self.press(self.flt(policies()), ca.VK_SNAPSHOT)
        self.assertEqual(r[(ca.VK_SNAPSHOT, "down")], (True, False))
        self.assertEqual(r[(ca.VK_SNAPSHOT, "up")], (True, False))

    def test_win_shift_s_swallowed_with_mask_key(self):
        r = self.press(self.flt(policies()), ca.VK_LWIN, ca.VK_LSHIFT, ca.VK_S)
        self.assertEqual(r[(ca.VK_S, "down")], (True, True))   # nuốt S + bấm phím mask
        self.assertEqual(r[(ca.VK_S, "up")], (True, False))
        self.assertEqual(r[(ca.VK_LWIN, "up")], (False, False))  # phím Win vẫn đi bình thường

    def test_normal_typing_not_affected(self):
        f = self.flt(policies())
        self.assertEqual(self.press(f, ca.VK_S)[(ca.VK_S, "down")], (False, False))           # gõ s
        self.assertEqual(self.press(f, ca.VK_LSHIFT, ca.VK_S)[(ca.VK_S, "down")], (False, False))  # S hoa
        self.assertEqual(self.press(f, ca.VK_LWIN, ca.VK_S)[(ca.VK_S, "down")], (False, False))    # Win+S tìm kiếm

    def test_other_capture_combos(self):
        f = self.flt(policies())
        self.assertTrue(self.press(f, ca.VK_LWIN, ca.VK_LSHIFT, ca.VK_R)[(ca.VK_R, "down")][0])
        self.assertTrue(self.press(f, ca.VK_LWIN, ca.VK_LMENU, ca.VK_R)[(ca.VK_R, "down")][0])
        self.assertTrue(self.press(f, ca.VK_LWIN, ca.VK_SNAPSHOT)[(ca.VK_SNAPSHOT, "down")][0])

    def test_not_governed_passes_through(self):
        r = self.press(self.flt(policies(exit_points=("CLIPBOARD",))), ca.VK_SNAPSHOT)
        self.assertEqual(r[(ca.VK_SNAPSHOT, "down")], (False, False))

    def test_report_only_passes_but_logs(self):
        r = self.press(self.flt(policies("REPORT_ONLY")), ca.VK_SNAPSHOT)
        self.assertEqual(r[(ca.VK_SNAPSHOT, "down")], (False, False))
        self.assertEqual(self.reports[0]["action_taken"], "LOGGED")

    def test_block_logged_and_reported_once_for_repeats(self):
        f = self.flt(policies())
        for _ in range(5):
            self.press(f, ca.VK_SNAPSHOT)
        self.assertEqual(len(self.reports), 1)   # bấm liên tục không spam log
        self.assertEqual(self.reports[0]["exit_point_type"], "SCREEN_CAPTURE")

    def test_injected_keys_ignored(self):
        f = self.flt(policies())
        self.assertEqual(f.on_key(ca.VK_SNAPSHOT, self.DOWN, injected=True), (False, False))


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
