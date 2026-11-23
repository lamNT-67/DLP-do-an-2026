"""
Clipboard + Screenshot Agent - DLP Agent
========================================
Chặn 2 exit point dùng chung cơ chế theo dõi clipboard của Windows:

  CLIPBOARD (copy-paste)
    * Copy chữ  -> Content Inspection Engine quét -> nhạy cảm thì xoá clipboard trước khi paste.
    * Copy file trong Explorer (Ctrl+C) -> inspect_file() từng file -> nhạy cảm thì xoá clipboard.

  SCREEN_CAPTURE (chụp màn hình) - 4 lớp:
    0. Chặn NGAY TỪ PHÍM BẤM: nuốt phím PrtSc và tổ hợp Win+Shift+S / Win+Shift+R / Win+Alt+R
       trước khi Windows kịp xử lý -> không có ảnh nào được tạo ra.
    1. Ảnh lọt vào clipboard (VD: mở Snipping Tool bằng chuột) -> xoá ngay.
    2. Win+PrtSc và Snipping Tool (Win 11) tự lưu file vào Pictures\\Screenshots -> xoá file mới.
    3. Tắt các công cụ chụp màn hình (Snipping Tool, Snip & Sketch) khi policy đang BLOCK.

Chạy dưới PHIÊN ĐĂNG NHẬP của người dùng (không chạy kiểu Windows Service được: service ở
Session 0 không nhìn thấy clipboard của user). Khi cài thật sẽ dùng Task Scheduler "At logon",
giống cách notify.ps1 của Long đang chạy.

    python clipboard_agent.py --demo           # thử ngay, không cần server (policy BLOCK giả lập)
    python clipboard_agent.py --demo --monitor # chỉ ghi nhận, không chặn
    python clipboard_agent.py                  # chạy thật: đọc config.ini, lấy policy từ server

Chỉ dùng thư viện chuẩn + psutil (đã có trong requirements.txt). Win32 API gọi qua ctypes.
"""

import argparse
import configparser
import datetime
import getpass
import json
import os
import signal
import socket
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple

import psutil

from content_inspection import (BLOCK_MIN_LEVEL, DEFAULT_FILE_TYPES, DEFAULT_RULES, _LEVEL_IDX,
                                inspect_file, scan_text, to_log_inspection, to_report_fields)
from log_writer import write_clipboard_delivery_status, write_log_event
from policy_utils import decision_status, evaluate_policies, get_exit_point_status

POLICY_REFRESH_SECONDS = 60
TICK_MS = 1000                 # mỗi giây: kiểm tra thư mục Screenshots + công cụ chụp màn hình
MAX_FILES_PER_COPY = 20        # copy nhiều file 1 lúc: chỉ quét 20 file đầu
SCREENSHOT_TOOLS = {"snippingtool.exe", "screensketch.exe", "screenclippinghost.exe"}
NOTICE_TEXT = "[DLP] Nội dung đã bị chặn do chứa dữ liệu nhạy cảm ({rules}). Liên hệ quản trị viên nếu cần."
NOTICE_IMAGE = "[DLP] Ảnh chụp màn hình đã bị chặn theo chính sách bảo mật."
NOTICE_FILES = "[DLP] Không được sao chép file nhạy cảm: {name}."
ACTION_BLOCK = "BLOCKED_DELETE"   # server chưa có action riêng cho clipboard -> dùng BLOCKED_DELETE
HOTKEY_LOG_GAP_SECONDS = 2        # giữ phím lâu / bấm liên tục: chỉ ghi log 1 lần mỗi 2 giây


class ClipboardEnforcement(NamedTuple):
    state: str
    reason: str | None = None


CLIPBOARD_REPLACED = ClipboardEnforcement("REPLACED")


def _now_iso():
    return datetime.datetime.now().astimezone().isoformat()


def _say(msg):
    print("[clipboard_agent %s] %s" % (time.strftime("%H:%M:%S"), msg), flush=True)


def policy_summary(policies):
    """Mô tả ngắn policy agent đang nhận, để in ra khi khởi động và khi policy thay đổi."""
    parts = []
    for ep in ("CLIPBOARD", "SCREEN_CAPTURE"):
        st = get_exit_point_status(policies, ep)
        if st["is_governed"]:
            parts.append("%s = %s (%d rule)" % (ep, st["effective_action"], len(st["content_rules"])))
        else:
            parts.append("%s = khong ap dung" % ep)
    if all("khong ap dung" in x for x in parts):
        return ("CHUA CO POLICY nao dang bat cho may nay -> agent chua chan gi. Kiem tra tren web: "
                "policy da tick 'Kich hoat policy', chon kenh CLIPBOARD/SCREEN_CAPTURE va gan dung may chua.")
    return "Policy: " + ", ".join(parts)


def screenshot_folders():
    home = Path.home()
    candidates = [home / "Pictures" / "Screenshots", home / "OneDrive" / "Pictures" / "Screenshots"]
    return [p for p in candidates if p.is_dir()]


# ============================================================================
# 1. LOGIC QUYẾT ĐỊNH (không phụ thuộc Windows -> test được ở mọi máy)
# ============================================================================
class ClipboardGuard:
    """Evaluate clipboard policy and record the result of the supplied replacement operation."""

    def __init__(self, hostname, get_policies, reporter=None):
        self.hostname = hostname
        self.get_policies = get_policies   # hàm trả về applicable_policies hiện tại
        self.reporter = reporter           # Returns the acknowledged server log ID or None.
        self.user = getpass.getuser()
        self._known_shots = {}             # thư mục Screenshots -> tập file đã thấy
        self._killed_pids = set()
        self._last_hotkey_log = {}

    # -------------------------------------------------- tiện ích
    def _status(self, exit_point):
        status = get_exit_point_status(self.get_policies(), exit_point)
        if exit_point == "SCREEN_CAPTURE" and status["is_governed"]:
            # Screen capture is governed by policy action alone.
            result = evaluate_policies(status, lambda current: {
                "verdict": "BLOCK" if current["effective_action"] == "BLOCK" else "LOG",
            })
            status.update(decision_status(status, result))
        return status

    def _record(self, exit_point, status, action, owner, target, inspection, report_fields=None):
        payload = {
            "hostname": self.hostname, "exit_point_type": exit_point,
            "policy_id": status["policy_ids"][0] if status["policy_ids"] else None,
            "action_taken": action, "occurred_at": _now_iso(), "file_path": None,
            "file_hash_sha256": None, "matched_rule_ids": [], "confidence_score": None,
            "destination_value": target.get("destination_domain"), "process_name": owner,
            "username": self.user,  # server đã có cột username trong bảng logs (Long thêm 03/11)
        }
        if report_fields:
            payload.update(report_fields)

        event_id = uuid.uuid4().hex
        reporter = self.reporter
        try:
            write_log_event(self.hostname, "clipboard", exit_point,
                            "violation" if action != "LOGGED" else "logged", status["effective_action"],
                            {"process_name": owner, "process_pid": None, "user": self.user},
                            target, inspection, action, False, event_id=event_id,
                            policy_id=payload["policy_id"], report_configured=reporter is not None, durable=True)
        except (OSError, UnicodeError):
            event_id = None
            _say("Khong ghi duoc log clipboard.")

        if reporter is None:
            return

        def record_delivery(status, server_log_id=None):
            if event_id is None:
                return
            try:
                write_clipboard_delivery_status(event_id, status, server_log_id=server_log_id)
            except OSError:
                _say("Khong ghi duoc trang thai gui bao cao clipboard.")

        def report():
            try:
                server_log_id = reporter(payload)
            except Exception:
                server_log_id = None
            if type(server_log_id) is int and server_log_id > 0:
                record_delivery("ACKNOWLEDGED", server_log_id)
            else:
                record_delivery("UNACKNOWLEDGED")
                _say("Khong nhan duoc xac nhan bao cao clipboard tu server.")

        try:
            threading.Thread(target=report, daemon=True).start()
        except RuntimeError:
            record_delivery("NOT_STARTED")
            _say("Khong khoi dong duoc luong gui bao cao clipboard.")

    @staticmethod
    def _enforce_clipboard(replace, notice):
        if replace is None:
            return ClipboardEnforcement("UNCHANGED", "NOT_ATTEMPTED")
        try:
            outcome = replace(notice)
        except Exception:
            return ClipboardEnforcement("UNCERTAIN", "REPLACEMENT_ERROR")
        if isinstance(outcome, ClipboardEnforcement):
            return outcome
        return ClipboardEnforcement("UNCERTAIN", "INVALID_RESULT")

    def _record_clipboard_result(self, exit_point, status, outcome, owner, target, inspection, report_fields=None):
        if outcome is not None:
            inspection = dict(inspection, enforcement_result=outcome.state)
            if outcome.reason is not None:
                inspection["enforcement_reason"] = outcome.reason
            report_fields = dict(report_fields or {}, enforcement_result=outcome.state)
        action = ACTION_BLOCK if outcome == CLIPBOARD_REPLACED else "LOGGED"
        self._record(exit_point, status, action, owner, target, inspection, report_fields)

    # -------------------------------------------------- chữ
    def on_text(self, text, owner=None, *, replace=None):
        """Return the policy's block decision and notice."""
        status = self._status("CLIPBOARD")
        if not status["is_governed"] or not text.strip():
            return False, None

        def evaluate(current):
            rules = current["content_rules"]
            blocking = current["effective_action"] == "BLOCK"
            if not rules:
                return {"verdict": "BLOCK" if blocking else "LOG",
                        "reason": "EXIT_POINT_BLOCKED" if blocking else "EXIT_POINT_MONITORED"}
            scan = scan_text(text, rules)
            if not scan["matched_rule_ids"]:
                return {"verdict": "ALLOW", "reason": "CLEAN"}
            block = blocking and _LEVEL_IDX[scan["confidence_level"]] >= _LEVEL_IDX[BLOCK_MIN_LEVEL]
            return dict(scan, verdict="BLOCK" if block else "LOG", reason="CONTENT_MATCH", real_type="text")

        result = evaluate_policies(status, evaluate)
        if result["verdict"] == "ALLOW":
            return False, None
        block = result["verdict"] == "BLOCK"
        status = decision_status(status, result)
        if result["reason"] == "CONTENT_MATCH":
            names = ", ".join(result["matched_rule_names"])
            inspection = to_log_inspection(result)
            report_fields = {"matched_rule_ids": result["matched_rule_ids"],
                             "confidence_score": result["confidence_level"]}
        else:
            names = "kênh bị khoá"
            inspection = {"verdict": result["verdict"], "reason": result["reason"]}
            report_fields = None
        notice = NOTICE_TEXT.format(rules=names)
        outcome = self._enforce_clipboard(replace, notice) if block else None
        self._record_clipboard_result("CLIPBOARD", status, outcome, owner,
                                      {"destination_domain": "Clipboard", "file_path": None},
                                      inspection, report_fields)
        if report_fields is not None:
            _say("%s chu (%s, %s) tu %s" % ("CHAN" if outcome == CLIPBOARD_REPLACED else "GHI NHAN",
                                             names, result["confidence_level"], owner or "?"))
        return block, notice

    # -------------------------------------------------- file copy trong Explorer
    def on_files(self, paths, owner=None, *, replace=None):
        status = self._status("CLIPBOARD")
        if not status["is_governed"]:
            return False, None
        findings = []
        blocked_name = None
        for path in [p for p in paths if os.path.isfile(p)][:MAX_FILES_PER_COPY]:
            res = inspect_file(path, status)
            if res["verdict"] == "ALLOW":
                continue
            findings.append(res)
            if res["verdict"] == "BLOCK" and blocked_name is None:
                blocked_name = res["file_name"]
        notice = NOTICE_FILES.format(name=blocked_name) if blocked_name else None
        outcome = self._enforce_clipboard(replace, notice) if notice else None
        for res in findings:
            file_outcome = outcome if res["verdict"] == "BLOCK" else None
            self._record_clipboard_result("CLIPBOARD", decision_status(status, res), file_outcome, owner,
                                          {"destination_domain": "Clipboard (copy file)", "file_path": res["file_path"]},
                                          to_log_inspection(res), to_report_fields(res))
            _say("%s file %s (%s, %s)" % ("CHAN" if file_outcome == CLIPBOARD_REPLACED else "GHI NHAN",
                                         res["file_name"], res["reason"], res["confidence_level"]))
        return bool(notice), notice

    # -------------------------------------------------- ảnh (chụp màn hình)
    def on_image(self, owner=None, *, replace=None):
        status = self._status("SCREEN_CAPTURE")
        if not status["is_governed"]:
            return False, None
        block = status["effective_action"] == "BLOCK"
        outcome = self._enforce_clipboard(replace, NOTICE_IMAGE) if block else None
        self._record_clipboard_result("SCREEN_CAPTURE", status, outcome, owner,
                                      {"destination_domain": "Clipboard (anh)", "file_path": None},
                                      {"verdict": "BLOCK" if block else "LOG", "reason": "SCREENSHOT_IN_CLIPBOARD"})
        _say("%s anh trong clipboard (tu %s)" % ("CHAN" if outcome == CLIPBOARD_REPLACED else "GHI NHAN",
                                                  owner or "PrintScreen"))
        return block, NOTICE_IMAGE

    # -------------------------------------------------- phím chụp màn hình
    def on_screenshot_hotkey(self, combo):
        """Gọi từ hook bàn phím, PHẢI trả lời thật nhanh (Windows gỡ hook nếu chậm quá ~300ms).
        Trả về True = nuốt phím. Ghi log chạy ở luồng nền."""
        status = self._status("SCREEN_CAPTURE")
        if not status["is_governed"]:
            return False
        block = status["effective_action"] == "BLOCK"
        now = time.monotonic()
        if now - self._last_hotkey_log.get(combo, -1e9) >= HOTKEY_LOG_GAP_SECONDS:
            self._last_hotkey_log[combo] = now
            action = ACTION_BLOCK if block else "LOGGED"
            threading.Thread(target=self._record, daemon=False, args=(
                "SCREEN_CAPTURE", status, action, "Ban phim: " + combo,
                {"destination_domain": "Phim chup man hinh", "file_path": None},
                {"verdict": "BLOCK" if block else "LOG", "reason": "SCREENSHOT_HOTKEY"})).start()
            _say("%s phim %s" % ("CHAN" if block else "GHI NHAN", combo))
        return block

    # -------------------------------------------------- chạy mỗi giây
    def tick(self):
        status = self._status("SCREEN_CAPTURE")
        if not status["is_governed"]:
            self._known_shots.clear()
            return
        block = status["effective_action"] == "BLOCK"
        self._check_screenshot_folders(status, block)
        if block:
            self._kill_screenshot_tools(status)

    def _check_screenshot_folders(self, status, block):
        for folder in screenshot_folders():
            try:
                current = {p.name for p in folder.iterdir() if p.is_file()}
            except OSError:
                continue
            if folder not in self._known_shots:      # lần đầu: chỉ ghi nhớ file cũ, không xoá
                self._known_shots[folder] = current
                continue
            for name in sorted(current - self._known_shots[folder]):
                path = folder / name
                deleted = False
                if block:
                    for _ in range(5):                 # file có thể đang được ghi dở
                        try:
                            path.unlink()
                            deleted = True
                            break
                        except PermissionError:
                            time.sleep(0.2)
                        except FileNotFoundError:
                            break
                action = ACTION_BLOCK if deleted else "LOGGED"
                self._record("SCREEN_CAPTURE", status, action, "Windows Screenshot",
                             {"destination_domain": "Pictures\\Screenshots", "file_path": str(path)},
                             {"verdict": "BLOCK" if deleted else "LOG", "reason": "SCREENSHOT_FILE"})
                _say("%s file chup man hinh %s" % ("XOA" if deleted else "GHI NHAN", name))
            self._known_shots[folder] = current

    def _kill_screenshot_tools(self, status):
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                name = (proc.info["name"] or "").lower()
                if name not in SCREENSHOT_TOOLS:
                    continue
                proc.terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            if proc.pid not in self._killed_pids:     # mỗi tiến trình chỉ ghi log 1 lần
                self._killed_pids.add(proc.pid)
                self._record("SCREEN_CAPTURE", status, "BLOCKED_KILL", name,
                             {"destination_domain": "Cong cu chup man hinh", "file_path": None},
                             {"verdict": "BLOCK", "reason": "SCREENSHOT_TOOL"})
                _say("TAT cong cu chup man hinh %s (PID %d)" % (name, proc.pid))


def is_screenshot(data, owner):
    """Ảnh CHỈ có ảnh (không kèm chữ) mới là chụp màn hình.
    Excel/Word khi copy ô/đoạn văn cũng bỏ kèm 1 tấm ảnh, nhưng luôn có chữ đi cùng."""
    if (owner or "").lower() in SCREENSHOT_TOOLS:
        return True
    return data["image"] and not (data["text"] or "").strip() and not data["files"]


def route_clipboard(guard, data, owner, *, replace=None):
    """Quyết định nội dung clipboard thuộc loại nào và giao cho đúng hàm xử lý."""
    if data["files"]:
        return guard.on_files(data["files"], owner, replace=replace)
    if is_screenshot(data, owner):
        return guard.on_image(owner, replace=replace)
    if data["text"]:
        return guard.on_text(data["text"], owner, replace=replace)
    return False, None


# Mã phím ảo (virtual-key) của Windows
VK_SNAPSHOT, VK_SHIFT, VK_LSHIFT, VK_RSHIFT = 0x2C, 0x10, 0xA0, 0xA1
VK_MENU, VK_LMENU, VK_RMENU, VK_LWIN, VK_RWIN = 0x12, 0xA4, 0xA5, 0x5B, 0x5C
VK_S, VK_R = 0x53, 0x52
VK_MASK = 0xE8   # phím "trống", bấm giả để Windows không mở menu Start khi ta nuốt phím sau Win
WM_KEYDOWN, WM_KEYUP, WM_SYSKEYDOWN, WM_SYSKEYUP = 0x0100, 0x0101, 0x0104, 0x0105
LLKHF_INJECTED = 0x10


class HotkeyFilter:
    """Theo dõi phím bổ trợ (Win, Shift, Alt) và quyết định có nuốt phím hay không.

    Nuốt:  PrtSc (mọi kiểu: PrtSc, Alt+PrtSc, Win+PrtSc, Win+Alt+PrtSc)
           Win+Shift+S (chụp vùng), Win+Shift+R (quay màn hình bằng Snipping Tool),
           Win+Alt+R (quay màn hình bằng Game Bar)
    Phím nhả (key up) của phím đã nuốt cũng bị nuốt theo để Windows không thấy nửa vời.
    """

    def __init__(self, decide):
        self.decide = decide        # hàm(tên_tổ_hợp) -> True nếu phải chặn
        self.win = self.shift = self.alt = False
        self.swallowed = set()      # phím đã nuốt lúc nhấn -> nuốt luôn lúc nhả

    def _combo(self, vk):
        if vk == VK_SNAPSHOT:
            return "PrtSc"
        if self.win and self.shift and vk == VK_S:
            return "Win+Shift+S"
        if self.win and self.shift and vk == VK_R:
            return "Win+Shift+R"
        if self.win and self.alt and vk == VK_R:
            return "Win+Alt+R"
        return None

    def on_key(self, vk, msg, injected=False):
        """Trả về (nuốt: bool, cần_bấm_phím_mask: bool)."""
        down = msg in (WM_KEYDOWN, WM_SYSKEYDOWN)
        if injected:
            return False, False     # phím do chương trình gửi (kể cả phím mask của ta) -> bỏ qua
        if vk in (VK_LWIN, VK_RWIN):
            self.win = down
        elif vk in (VK_SHIFT, VK_LSHIFT, VK_RSHIFT):
            self.shift = down
        elif vk in (VK_MENU, VK_LMENU, VK_RMENU):
            self.alt = down
        if not down:
            if vk in self.swallowed:
                self.swallowed.discard(vk)
                return True, False
            return False, False
        combo = self._combo(vk)
        if combo and self.decide(combo):
            self.swallowed.add(vk)
            return True, combo != "PrtSc"   # tổ hợp có Win -> bấm phím mask chống mở Start
        return False, False


# ============================================================================
# 2. LỚP WINDOWS: lắng nghe clipboard qua Win32 API (ctypes)
# ============================================================================
CF_TEXT_UNICODE, CF_HDROP, CF_BITMAP, CF_DIB, CF_DIBV5 = 13, 15, 2, 8, 17
WM_CLIPBOARDUPDATE, WM_TIMER = 0x031D, 0x0113
GMEM_MOVEABLE = 0x0002
SCREENSHOT_TIMER, CLIPBOARD_READ_TIMER = 1, 2
CLIPBOARD_QUIET_NS = 25_000_000
CLIPBOARD_DEFERRAL_CAP_NS = 50_000_000
USER_TIMER_MINIMUM_NS = 10_000_000
CLIPBOARD_OWNER_CHANGED = object()


@dataclass
class PendingClipboardRead:
    started_ns: int
    due_ns: int
    sequence: int
    coalesced: int = 0
    superseded: int = 0

    def observe_sequence(self, sequence):
        if self.sequence and sequence and sequence != self.sequence:
            self.superseded += 1
        self.sequence = sequence


def _load_win32():
    import ctypes
    from ctypes import wintypes as w
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    LRESULT = ctypes.c_ssize_t
    WNDPROC = ctypes.WINFUNCTYPE(LRESULT, w.HWND, w.UINT, w.WPARAM, w.LPARAM)

    class WNDCLASSW(ctypes.Structure):
        _fields_ = [("style", w.UINT), ("lpfnWndProc", WNDPROC), ("cbClsExtra", ctypes.c_int),
                    ("cbWndExtra", ctypes.c_int), ("hInstance", w.HINSTANCE), ("hIcon", w.HANDLE),
                    ("hCursor", w.HANDLE), ("hbrBackground", w.HANDLE), ("lpszMenuName", w.LPCWSTR),
                    ("lpszClassName", w.LPCWSTR)]

    HOOKPROC = ctypes.WINFUNCTYPE(LRESULT, ctypes.c_int, w.WPARAM, w.LPARAM)

    class KBDLLHOOKSTRUCT(ctypes.Structure):
        _fields_ = [("vkCode", w.DWORD), ("scanCode", w.DWORD), ("flags", w.DWORD),
                    ("time", w.DWORD), ("dwExtraInfo", ctypes.c_size_t)]

    sig = {  # khai báo kiểu đầy đủ: thiếu restype là handle 64-bit bị cắt -> crash
        (user32, "SetWindowsHookExW"): ([ctypes.c_int, HOOKPROC, w.HINSTANCE, w.DWORD], w.HANDLE),
        (user32, "CallNextHookEx"): ([w.HANDLE, ctypes.c_int, w.WPARAM, w.LPARAM], LRESULT),
        (user32, "UnhookWindowsHookEx"): ([w.HANDLE], w.BOOL),
        (user32, "keybd_event"): ([w.BYTE, w.BYTE, w.DWORD, ctypes.c_size_t], None),
        (user32, "RegisterClassW"): ([ctypes.POINTER(WNDCLASSW)], w.ATOM),
        (user32, "CreateWindowExW"): ([w.DWORD, w.LPCWSTR, w.LPCWSTR, w.DWORD, ctypes.c_int, ctypes.c_int,
                                       ctypes.c_int, ctypes.c_int, w.HWND, w.HMENU, w.HINSTANCE,
                                       w.LPVOID], w.HWND),
        (user32, "DefWindowProcW"): ([w.HWND, w.UINT, w.WPARAM, w.LPARAM], LRESULT),
        (user32, "AddClipboardFormatListener"): ([w.HWND], w.BOOL),
        (user32, "RemoveClipboardFormatListener"): ([w.HWND], w.BOOL),
        (user32, "GetMessageW"): ([ctypes.POINTER(w.MSG), w.HWND, w.UINT, w.UINT], w.BOOL),
        (user32, "TranslateMessage"): ([ctypes.POINTER(w.MSG)], w.BOOL),
        (user32, "DispatchMessageW"): ([ctypes.POINTER(w.MSG)], LRESULT),
        (user32, "PostQuitMessage"): ([ctypes.c_int], None),
        (user32, "SetTimer"): ([w.HWND, ctypes.c_size_t, w.UINT, ctypes.c_void_p], ctypes.c_size_t),
        (user32, "KillTimer"): ([w.HWND, ctypes.c_size_t], w.BOOL),
        (user32, "OpenClipboard"): ([w.HWND], w.BOOL),
        (user32, "CloseClipboard"): ([], w.BOOL),
        (user32, "EmptyClipboard"): ([], w.BOOL),
        (user32, "IsClipboardFormatAvailable"): ([w.UINT], w.BOOL),
        (user32, "GetClipboardData"): ([w.UINT], w.HANDLE),
        (user32, "SetClipboardData"): ([w.UINT, w.HANDLE], w.HANDLE),
        (user32, "GetClipboardSequenceNumber"): ([], w.DWORD),
        (user32, "GetClipboardOwner"): ([], w.HWND),
        (user32, "GetOpenClipboardWindow"): ([], w.HWND),
        (user32, "GetWindowThreadProcessId"): ([w.HWND, ctypes.POINTER(w.DWORD)], w.DWORD),
        (user32, "RegisterClipboardFormatW"): ([w.LPCWSTR], w.UINT),
        (kernel32, "GlobalLock"): ([w.HANDLE], ctypes.c_void_p),
        (kernel32, "GlobalUnlock"): ([w.HANDLE], w.BOOL),
        (kernel32, "GlobalAlloc"): ([w.UINT, ctypes.c_size_t], w.HANDLE),
        (kernel32, "GlobalFree"): ([w.HANDLE], w.HANDLE),
        (kernel32, "GlobalSize"): ([w.HANDLE], ctypes.c_size_t),
        (kernel32, "GetModuleHandleW"): ([w.LPCWSTR], w.HMODULE),
        (shell32, "DragQueryFileW"): ([w.HANDLE, w.UINT, w.LPWSTR, w.UINT], w.UINT),
    }
    for (dll, name), (args, res) in sig.items():
        fn = getattr(dll, name)
        fn.argtypes, fn.restype = args, res
    return ctypes, w, user32, kernel32, shell32, WNDPROC, WNDCLASSW, HOOKPROC, KBDLLHOOKSTRUCT


class ClipboardWatcher:
    """Cửa sổ ẩn nhận thông báo WM_CLIPBOARDUPDATE mỗi khi clipboard thay đổi."""

    def __init__(self, guard, *, trace_native_clipboard=False, defer_clipboard_read=False):
        (self.ct, self.w, self.user32, self.kernel32, self.shell32,
         WNDPROC, WNDCLASSW, HOOKPROC, self.KBD) = _load_win32()
        self.guard = guard
        self.trace_native_clipboard = trace_native_clipboard
        self.defer_clipboard_read = defer_clipboard_read
        self._pending_clipboard_read = None
        self.cf_png = self.user32.RegisterClipboardFormatW("PNG")
        self._proc = WNDPROC(self._wndproc)  # giữ tham chiếu, không thì bị thu hồi -> crash
        hinst = self.kernel32.GetModuleHandleW(None)
        wc = WNDCLASSW()
        wc.lpfnWndProc, wc.hInstance, wc.lpszClassName = self._proc, hinst, "DLPClipboardWatcher"
        self.user32.RegisterClassW(self.ct.byref(wc))
        HWND_MESSAGE = self.w.HWND(-3)       # cửa sổ chỉ để nhận tin nhắn, không hiện lên màn hình
        self.hwnd = self.user32.CreateWindowExW(0, "DLPClipboardWatcher", "DLP", 0, 0, 0, 0, 0,
                                                HWND_MESSAGE, None, hinst, None)
        if not self.hwnd:
            raise OSError("Khong tao duoc cua so lang nghe (loi %d)" % self.ct.get_last_error())
        if not self.user32.AddClipboardFormatListener(self.hwnd):
            raise OSError("AddClipboardFormatListener that bai (loi %d)" % self.ct.get_last_error())
        self.user32.SetTimer(self.hwnd, SCREENSHOT_TIMER, TICK_MS, None)
        # Hook bàn phím mức thấp: chạy trên chính luồng có vòng lặp tin nhắn này
        self.keys = HotkeyFilter(self.guard.on_screenshot_hotkey)
        self._hook_proc = HOOKPROC(self._keyboard_hook)  # giữ tham chiếu, tránh bị thu hồi
        self.hook = self.user32.SetWindowsHookExW(13, self._hook_proc, hinst, 0)  # 13 = WH_KEYBOARD_LL
        if not self.hook:
            _say("Canh bao: khong cai duoc hook ban phim (loi %d), chi con cac lop chan khac."
                 % self.ct.get_last_error())

    # -------------------------------------------------- vòng lặp tin nhắn
    def run(self):
        msg = self.w.MSG()
        # Ctrl+C: thay vì ném KeyboardInterrupt (hay rơi đúng vào giữa hook bàn phím và bị nuốt mất),
        # ta xin Windows kết thúc vòng lặp tin nhắn một cách gọn gàng.
        old_handler = signal.signal(signal.SIGINT, lambda *_: self.user32.PostQuitMessage(0))
        try:
            while self.user32.GetMessageW(self.ct.byref(msg), None, 0, 0) > 0:
                self.user32.TranslateMessage(self.ct.byref(msg))
                self.user32.DispatchMessageW(self.ct.byref(msg))
        finally:
            signal.signal(signal.SIGINT, old_handler)
            if self._pending_clipboard_read is not None:
                self._pending_clipboard_read = None
                self.user32.KillTimer(self.hwnd, CLIPBOARD_READ_TIMER)
                self._clipboard_diagnostic("read_abandoned_on_shutdown")
            self.user32.RemoveClipboardFormatListener(self.hwnd)
            if self.hook:
                self.user32.UnhookWindowsHookEx(self.hook)

    def _keyboard_hook(self, code, wparam, lparam):
        try:
            if code == 0:  # HC_ACTION
                kb = self.ct.cast(lparam, self.ct.POINTER(self.KBD)).contents
                swallow, mask = self.keys.on_key(kb.vkCode, wparam, bool(kb.flags & LLKHF_INJECTED))
                if mask:
                    self.user32.keybd_event(VK_MASK, 0, 0, 0)
                    self.user32.keybd_event(VK_MASK, 0, 2, 0)  # 2 = KEYEVENTF_KEYUP
                if swallow:
                    return 1  # trả về khác 0 = nuốt phím, Windows và các ứng dụng không nhận được
        except KeyboardInterrupt:
            self.user32.PostQuitMessage(0)  # dự phòng nếu Ctrl+C vẫn rơi vào đây
        except Exception as e:
            _say("Loi hook ban phim: %s: %s" % (type(e).__name__, e))
        return self.user32.CallNextHookEx(None, code, wparam, lparam)

    def _wndproc(self, hwnd, msg, wparam, lparam):
        try:
            if msg == WM_CLIPBOARDUPDATE:
                if self.defer_clipboard_read:
                    self._schedule_clipboard_read()
                else:
                    self._on_clipboard_update()
                return 0
            if msg == WM_TIMER:
                if wparam == SCREENSHOT_TIMER:
                    self.guard.tick()
                elif wparam == CLIPBOARD_READ_TIMER:
                    pending = self._pending_clipboard_read
                    now = time.monotonic_ns()
                    # KillTimer can leave an old message queued.
                    if pending is not None and now >= pending.due_ns:
                        self._dispatch_pending_read(now)
                return 0
        except KeyboardInterrupt:
            self.user32.PostQuitMessage(0)
            return 0
        except Exception as e:  # lỗi trong callback không được làm chết agent
            _say("Loi xu ly: %s" % type(e).__name__)
        return self.user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def _clipboard_diagnostic(self, event, **fields):
        try:
            _say("clipboard_inspection " + json.dumps(dict(event=event, **fields), separators=(",", ":")))
        except OSError:
            pass

    def _schedule_clipboard_read(self):
        now = time.monotonic_ns()
        sequence = self.user32.GetClipboardSequenceNumber()
        pending = self._pending_clipboard_read
        if pending is None:
            pending = PendingClipboardRead(now, now + CLIPBOARD_QUIET_NS, sequence)
            self._pending_clipboard_read = pending
        else:
            pending.coalesced += 1
            pending.observe_sequence(sequence)
            if now >= pending.due_ns:
                self._dispatch_pending_read(now)
                return
            due_ns = min(now + CLIPBOARD_QUIET_NS, pending.started_ns + CLIPBOARD_DEFERRAL_CAP_NS)
            # Keep the earlier timer if Windows would round a rearm past the cap.
            if due_ns == pending.due_ns or due_ns - now < USER_TIMER_MINIMUM_NS:
                return
            pending.due_ns = due_ns
        delay_ms = (pending.due_ns - now + 999_999) // 1_000_000
        if not self.user32.SetTimer(self.hwnd, CLIPBOARD_READ_TIMER, delay_ms, None):
            self._dispatch_pending_read(now, timer_error=self.ct.get_last_error())

    def _dispatch_pending_read(self, now, *, timer_error=None):
        pending = self._pending_clipboard_read
        self._pending_clipboard_read = None
        self.user32.KillTimer(self.hwnd, CLIPBOARD_READ_TIMER)
        try:
            self._on_clipboard_update(pending)
        finally:
            if self.trace_native_clipboard or pending.coalesced or pending.superseded or timer_error is not None:
                self._clipboard_diagnostic(
                    "timer_fallback" if timer_error is not None else "deferred_read",
                    deferral_ms=(now - pending.started_ns) / 1e6,
                    coalesced_notifications=pending.coalesced,
                    observed_sequence_changes=pending.superseded,
                    timer_error=timer_error,
                )

    # -------------------------------------------------- đọc / ghi clipboard
    def _open(self):
        for _ in range(10):  # ứng dụng vừa copy có thể vẫn đang giữ clipboard
            if self.user32.OpenClipboard(self.hwnd):
                return True
            time.sleep(0.02)
        return False

    def _start_native_trace(self):
        if self.trace_native_clipboard:
            return {"started_utc": _now_iso(), "started_ns": time.perf_counter_ns()}
        return None

    def _finish_native_trace(self, phase, trace, *, closed=None, close_error=None):
        if trace is not None:
            finished_ns = time.perf_counter_ns()
            started_ns = trace.pop("started_ns")
            opened_ns = trace.pop("opened_ns", None)
            trace.update(
                phase=phase, pid=os.getpid(), tid=threading.get_native_id(), hwnd=hex(self.hwnd),
                finished_utc=_now_iso(), open_ok=opened_ns is not None, close_ok=closed,
                open_ms=(finished_ns - started_ns if opened_ns is None else opened_ns - started_ns) / 1e6,
                hold_until_close_return_ms=None if opened_ns is None else (finished_ns - opened_ns) / 1e6,
                close_error=close_error,
            )
            if closed is False:
                opener = self.user32.GetOpenClipboardWindow()
                trace["opener_after_failed_close"] = hex(opener) if opener else None
            message = "clipboard_native " + json.dumps(trace, separators=(",", ":"))
        elif closed is False:
            message = "CloseClipboard failed phase=%s winerror=%d" % (phase, close_error)
        else:
            return
        try:
            _say(message)
        except OSError:
            pass  # Diagnostic output must not change the clipboard result.

    def _close_clipboard(self, phase, trace):
        closed = bool(self.user32.CloseClipboard())
        error = None if closed else self.ct.get_last_error()
        self._finish_native_trace(phase, trace, closed=closed, close_error=error)
        return closed

    def _get_clipboard_data(self, clipboard_format, trace):
        if trace is None:
            return self.user32.GetClipboardData(clipboard_format)
        started_ns = time.perf_counter_ns()
        try:
            return self.user32.GetClipboardData(clipboard_format)
        finally:
            trace.setdefault("get_data_ms", {})[clipboard_format] = (time.perf_counter_ns() - started_ns) / 1e6

    def _owner_name(self, owner):
        if not owner:
            return None
        pid = self.w.DWORD()
        self.user32.GetWindowThreadProcessId(owner, self.ct.byref(pid))
        try:
            return psutil.Process(pid.value).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):
            return None

    def _read(self, pending=None):
        """Snapshot data, owner, and sequence under the same clipboard lock."""
        trace = self._start_native_trace()
        unreadable = set() if pending is not None else None
        if not self._open():
            self._finish_native_trace("read", trace)
            if pending is not None:
                self._clipboard_diagnostic("read_open_failed")
            return None
        try:
            if trace is not None:
                trace["opened_ns"] = time.perf_counter_ns()
            snapshot = self._read_open_clipboard(trace, pending, unreadable)
        finally:
            closed = self._close_clipboard("read", trace)
            if unreadable:
                self._clipboard_diagnostic("unreadable_advertised_formats", formats=sorted(unreadable))
        if closed and snapshot is CLIPBOARD_OWNER_CHANGED:
            self._clipboard_diagnostic("owner_changed_during_read")
            return None
        if closed and snapshot is not None and unreadable:
            snapshot[0]["unreadable_formats"] = unreadable
        return snapshot if closed else None

    def _read_open_clipboard(self, trace, pending, unreadable):
        u = self.user32
        owner = u.GetClipboardOwner()
        if pending is not None:
            # Sample before requesting data, since rendering can advance the sequence.
            pending.observe_sequence(u.GetClipboardSequenceNumber())
        if trace is not None:
            trace["owner_hwnd"] = hex(owner) if owner else None
        if owner == self.hwnd:
            return None  # An update caused by our own notice or by clearing the clipboard.

        data = {"text": None, "files": [], "image": False}
        if u.IsClipboardFormatAvailable(CF_HDROP):
            if unreadable is not None:
                unreadable.add(CF_HDROP)
            h = self._get_clipboard_data(CF_HDROP, trace)
            if h:
                count = self.shell32.DragQueryFileW(h, 0xFFFFFFFF, None, 0)
                for i in range(min(count, MAX_FILES_PER_COPY)):
                    n = self.shell32.DragQueryFileW(h, i, None, 0)
                    buf = self.ct.create_unicode_buffer(n + 1)
                    self.shell32.DragQueryFileW(h, i, buf, n + 1)
                    data["files"].append(buf.value)
                if unreadable is not None and data["files"] and all(data["files"]):
                    unreadable.discard(CF_HDROP)
        if u.IsClipboardFormatAvailable(CF_TEXT_UNICODE):
            if unreadable is not None:
                unreadable.add(CF_TEXT_UNICODE)
            h = self._get_clipboard_data(CF_TEXT_UNICODE, trace)
            if h:
                p = self.kernel32.GlobalLock(h)
                if p:
                    try:
                        size = self.kernel32.GlobalSize(h) // 2
                        data["text"] = self.ct.wstring_at(p, size).split("\0", 1)[0]
                        if unreadable is not None and size:
                            unreadable.discard(CF_TEXT_UNICODE)
                    finally:
                        self.kernel32.GlobalUnlock(h)
        data["image"] = any(u.IsClipboardFormatAvailable(f)
                            for f in (CF_BITMAP, CF_DIB, CF_DIBV5, self.cf_png) if f)
        if pending is not None and u.GetClipboardOwner() != owner:
            return CLIPBOARD_OWNER_CHANGED
        # Reading a delayed format can itself advance the sequence.
        return data, owner, u.GetClipboardSequenceNumber()

    def _replace_with_notice(self, notice, seq_before, owner_before=None):
        """Replace the inspected clipboard snapshot and return the observed outcome."""
        u, k = self.user32, self.kernel32
        if not seq_before:
            return ClipboardEnforcement("UNCHANGED", "SEQUENCE_UNAVAILABLE")
        if u.GetClipboardSequenceNumber() != seq_before:
            return ClipboardEnforcement("UNCHANGED", "SEQUENCE_CHANGED")
        try:
            raw = (notice + "\0").encode("utf-16-le")
        except (UnicodeError, MemoryError):
            return ClipboardEnforcement("UNCHANGED", "NOTICE_WRITE_FAILED")
        hmem = k.GlobalAlloc(GMEM_MOVEABLE, len(raw))
        if not hmem:
            return ClipboardEnforcement("UNCHANGED", "GLOBAL_ALLOC_FAILED")
        try:
            p = k.GlobalLock(hmem)
            if not p:
                return ClipboardEnforcement("UNCHANGED", "GLOBAL_LOCK_FAILED")
            try:
                self.ct.memmove(p, raw, len(raw))
            except Exception:
                return ClipboardEnforcement("UNCHANGED", "NOTICE_WRITE_FAILED")
            finally:
                self.ct.set_last_error(0)
                unlocked = not k.GlobalUnlock(hmem) and not self.ct.get_last_error()
            if not unlocked:
                return ClipboardEnforcement("UNCHANGED", "GLOBAL_UNLOCK_FAILED")

            trace = self._start_native_trace()
            if not self._open():
                self._finish_native_trace("replace", trace)
                return ClipboardEnforcement("UNCHANGED", "OPEN_CLIPBOARD_FAILED")
            try:
                if trace is not None:
                    trace["opened_ns"] = time.perf_counter_ns()
                # The sequence can change while preparing the notice or waiting for OpenClipboard.
                if u.GetClipboardSequenceNumber() != seq_before:
                    outcome = ClipboardEnforcement("UNCHANGED", "SEQUENCE_CHANGED")
                elif self.defer_clipboard_read and u.GetClipboardOwner() != owner_before:
                    outcome = ClipboardEnforcement("UNCHANGED", "OWNER_CHANGED")
                elif not u.EmptyClipboard():
                    state = "UNCHANGED" if u.GetClipboardSequenceNumber() == seq_before else "UNCERTAIN"
                    outcome = ClipboardEnforcement(state, "EMPTY_CLIPBOARD_FAILED")
                elif not u.SetClipboardData(CF_TEXT_UNICODE, hmem):
                    outcome = ClipboardEnforcement("CLEARED_WITHOUT_NOTICE", "SET_CLIPBOARD_DATA_FAILED")
                else:
                    hmem = None  # Windows owns the handle after a successful SetClipboardData.
                    outcome = CLIPBOARD_REPLACED
            finally:
                closed = self._close_clipboard("replace", trace)
            if not closed:
                return ClipboardEnforcement("UNCERTAIN", "CLOSE_CLIPBOARD_FAILED")
            return outcome
        finally:
            if hmem:
                k.GlobalFree(hmem)

    def _on_clipboard_update(self, pending=None):
        snapshot = self._read(pending)
        if snapshot is None:
            return
        data, owner, seq = snapshot
        owner_name = self._owner_name(owner)
        # Unreadable text does not establish that a mixed clipboard is image-only.
        if (CF_TEXT_UNICODE in data.get("unreadable_formats", ()) and data["image"]
                and not data["files"] and (owner_name or "").lower() not in SCREENSHOT_TOOLS):
            return
        route_clipboard(self.guard, data, owner_name,
                        replace=lambda notice: self._replace_with_notice(notice, seq, owner))


# ============================================================================
# 3. KHỞI ĐỘNG: chế độ demo (không server) hoặc chạy thật (lấy policy từ server)
# ============================================================================
def demo_policies(monitor_only):
    action = "REPORT_ONLY" if monitor_only else "BLOCK"
    return [{"policy_id": None, "action": action, "exit_points": ["CLIPBOARD", "SCREEN_CAPTURE"],
             "content_rules": DEFAULT_RULES, "file_types": DEFAULT_FILE_TYPES,
             "allowed_files": [], "allowed_locations": []}]


class ServerPolicy:
    """Lấy policy định kỳ ở luồng nền. Dùng token có sẵn trong config.ini (do service
    của agent chính đăng ký), KHÔNG tự đăng ký để tránh 2 tiến trình cùng đăng ký 1 máy."""

    def __init__(self, config_path):
        from policy_client import PolicyClient
        self.config_path, self.PolicyClient = config_path, PolicyClient
        self.client, self.hostname, self.policies = None, None, []
        self._last_summary = None
        self._lock = threading.Lock()

    def _connect(self):
        cfg = configparser.ConfigParser()
        cfg.read(self.config_path, encoding="utf-8")
        a = cfg["agent"]
        token = a.get("api_token", "").strip()
        if not token:
            return False
        self.hostname = a.get("hostname", socket.gethostname())
        self.client = self.PolicyClient(a["server_url"], self.hostname, token)
        return True

    def start(self):
        while not self._connect():
            _say("config.ini chua co api_token (agent chinh chua dang ky), thu lai sau 30s...")
            time.sleep(30)
        self._fetch()  # lấy policy lần đầu ngay, không để khoảng trống không được bảo vệ
        threading.Thread(target=self._loop, daemon=True).start()

    def _fetch(self):
        data = self.client.get_policy()
        if data is None:
            _say("Khong lay duoc policy tu server, tam dung policy cu (lan sau thu lai).")
            return
        with self._lock:
            self.policies = data.get("applicable_policies", [])
        summary = policy_summary(self.policies)
        if summary != self._last_summary:   # chỉ in khi policy thay đổi, tránh in lặp mỗi phút
            self._last_summary = summary
            _say(summary)

    def _loop(self):
        while True:
            time.sleep(POLICY_REFRESH_SECONDS)
            self._fetch()

    def get(self):
        with self._lock:
            return list(self.policies)

    def report(self, payload):
        return self.client.send_report(payload, require_ack=True)


def main(argv=None):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    ap = argparse.ArgumentParser(description="DLP Clipboard + Screenshot Agent")
    ap.add_argument("--demo", action="store_true", help="chay thu khong can server")
    ap.add_argument("--monitor", action="store_true", help="(voi --demo) chi ghi nhan, khong chan")
    ap.add_argument("--trace-native-clipboard", action="store_true",
                    help="trace clipboard open, read and close timing to stdout")
    ap.add_argument("--defer-clipboard-read", action="store_true",
                    help="enable experimental deferred clipboard acquisition")
    ap.add_argument("--config", default=str(Path(__file__).with_name("config.ini")))
    args = ap.parse_args(argv)
    if sys.platform != "win32":
        print("clipboard_agent chi chay tren Windows.")
        return 1
    if args.demo:
        policies = demo_policies(args.monitor)
        guard = ClipboardGuard(socket.gethostname(), lambda: policies)
        _say("CHE DO DEMO (%s) - khong ket noi server." % ("chi ghi nhan" if args.monitor else "CHAN"))
        _say(policy_summary(policies))
    else:
        sp = ServerPolicy(args.config)
        sp.start()
        guard = ClipboardGuard(sp.hostname, sp.get, sp.report)
        _say("Ket noi server voi may %s." % sp.hostname)
    watcher = ClipboardWatcher(guard, trace_native_clipboard=args.trace_native_clipboard,
                               defer_clipboard_read=args.defer_clipboard_read)
    _say("Dang theo doi clipboard va chup man hinh. Bam Ctrl+C de dung.")
    try:
        watcher.run()
    except KeyboardInterrupt:
        pass
    _say("Da dung.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
