"""
Clipboard + Screenshot Agent - DLP Agent
========================================
Chặn 2 exit point dùng chung cơ chế theo dõi clipboard của Windows:

  CLIPBOARD (copy-paste)
    * Copy chữ  -> Content Inspection Engine quét -> nhạy cảm thì xoá clipboard trước khi paste.
    * Copy file trong Explorer (Ctrl+C) -> inspect_file() từng file -> nhạy cảm thì xoá clipboard.

  SCREEN_CAPTURE (chụp màn hình) - 3 lớp:
    1. PrtSc / Win+Shift+S / Snipping Tool đều đẩy ẢNH vào clipboard -> xoá ngay.
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
import os
import socket
import sys
import threading
import time
from pathlib import Path

import psutil

from content_inspection import (BLOCK_MIN_LEVEL, DEFAULT_FILE_TYPES, DEFAULT_RULES, _LEVEL_IDX,
                                inspect_file, scan_text, to_log_inspection, to_report_fields)
from log_writer import write_log_event
from policy_utils import get_exit_point_status

POLICY_REFRESH_SECONDS = 60
TICK_MS = 1000                 # mỗi giây: kiểm tra thư mục Screenshots + công cụ chụp màn hình
MAX_FILES_PER_COPY = 20        # copy nhiều file 1 lúc: chỉ quét 20 file đầu
SCREENSHOT_TOOLS = {"snippingtool.exe", "screensketch.exe", "screenclippinghost.exe"}
NOTICE_TEXT = "[DLP] Nội dung đã bị chặn do chứa dữ liệu nhạy cảm ({rules}). Liên hệ quản trị viên nếu cần."
NOTICE_IMAGE = "[DLP] Ảnh chụp màn hình đã bị chặn theo chính sách bảo mật."
NOTICE_FILES = "[DLP] Không được sao chép file nhạy cảm: {name}."
ACTION_BLOCK = "BLOCKED_DELETE"   # server chưa có action riêng cho clipboard -> dùng BLOCKED_DELETE


def _now_iso():
    return datetime.datetime.now().astimezone().isoformat()


def _say(msg):
    print("[clipboard_agent %s] %s" % (time.strftime("%H:%M:%S"), msg), flush=True)


def screenshot_folders():
    home = Path.home()
    candidates = [home / "Pictures" / "Screenshots", home / "OneDrive" / "Pictures" / "Screenshots"]
    return [p for p in candidates if p.is_dir()]


# ============================================================================
# 1. LOGIC QUYẾT ĐỊNH (không phụ thuộc Windows -> test được ở mọi máy)
# ============================================================================
class ClipboardGuard:
    """Nhận sự kiện clipboard, hỏi policy + bộ não, trả về có xoá clipboard không."""

    def __init__(self, hostname, get_policies, reporter=None):
        self.hostname = hostname
        self.get_policies = get_policies   # hàm trả về applicable_policies hiện tại
        self.reporter = reporter           # hàm gửi report lên server (hoặc None)
        self.user = getpass.getuser()
        self._known_shots = {}             # thư mục Screenshots -> tập file đã thấy
        self._killed_pids = set()

    # -------------------------------------------------- tiện ích
    def _status(self, exit_point):
        return get_exit_point_status(self.get_policies(), exit_point)

    def _record(self, exit_point, status, action, owner, target, inspection, report_fields=None):
        payload = {
            "hostname": self.hostname, "exit_point_type": exit_point,
            "policy_id": status["policy_ids"][0] if status["policy_ids"] else None,
            "action_taken": action, "occurred_at": _now_iso(), "file_path": None,
            "file_hash_sha256": None, "matched_rule_ids": [], "confidence_score": None,
            "destination_value": target.get("destination_domain"), "process_name": owner,
        }
        if report_fields:
            payload.update(report_fields)
        reported = False
        if self.reporter:
            threading.Thread(target=self.reporter, args=(payload,), daemon=True).start()
            reported = True  # gửi nền, không chặn vòng lặp tin nhắn của Windows
        write_log_event(self.hostname, "clipboard", exit_point,
                        "violation" if action != "LOGGED" else "logged", status["effective_action"],
                        {"process_name": owner, "process_pid": None, "user": self.user},
                        target, inspection, action, reported)

    # -------------------------------------------------- chữ
    def on_text(self, text, owner=None):
        """Trả về (xoá_clipboard: bool, dòng_thông_báo | None)."""
        status = self._status("CLIPBOARD")
        if not status["is_governed"] or not text.strip():
            return False, None
        rules = status["content_rules"]
        if not rules:  # policy không có content rule: BLOCK = chặn mọi copy, REPORT_ONLY = ghi hết
            action = ACTION_BLOCK if status["effective_action"] == "BLOCK" else "LOGGED"
            self._record("CLIPBOARD", status, action, owner,
                         {"destination_domain": "Clipboard", "file_path": None},
                         {"verdict": "BLOCK" if action != "LOGGED" else "LOG",
                          "reason": "EXIT_POINT_BLOCKED" if action != "LOGGED" else "EXIT_POINT_MONITORED"})
            return action != "LOGGED", NOTICE_TEXT.format(rules="kênh bị khoá")
        scan = scan_text(text, rules)
        if not scan["matched_rule_ids"]:
            return False, None
        block = (status["effective_action"] == "BLOCK"
                 and _LEVEL_IDX[scan["confidence_level"]] >= _LEVEL_IDX[BLOCK_MIN_LEVEL])
        action = ACTION_BLOCK if block else "LOGGED"
        inspection = to_log_inspection(dict(scan, verdict="BLOCK" if block else "LOG",
                                            reason="CONTENT_MATCH", real_type="text"))
        self._record("CLIPBOARD", status, action, owner,
                     {"destination_domain": "Clipboard", "file_path": None}, inspection,
                     {"matched_rule_ids": scan["matched_rule_ids"],
                      "confidence_score": scan["confidence_level"]})
        names = ", ".join(scan["matched_rule_names"])
        _say("%s chu (%s, %s) tu %s" % ("CHAN" if block else "GHI NHAN", names,
                                         scan["confidence_level"], owner or "?"))
        return block, NOTICE_TEXT.format(rules=names)

    # -------------------------------------------------- file copy trong Explorer
    def on_files(self, paths, owner=None):
        status = self._status("CLIPBOARD")
        if not status["is_governed"]:
            return False, None
        blocked_name = None
        for path in [p for p in paths if os.path.isfile(p)][:MAX_FILES_PER_COPY]:
            res = inspect_file(path, status)
            if res["verdict"] == "ALLOW":
                continue
            action = ACTION_BLOCK if res["verdict"] == "BLOCK" else "LOGGED"
            self._record("CLIPBOARD", status, action, owner,
                         {"destination_domain": "Clipboard (copy file)", "file_path": path},
                         to_log_inspection(res), to_report_fields(res))
            _say("%s file %s (%s, %s)" % ("CHAN" if action != "LOGGED" else "GHI NHAN",
                                         res["file_name"], res["reason"], res["confidence_level"]))
            if action != "LOGGED" and blocked_name is None:
                blocked_name = res["file_name"]
        if blocked_name:
            return True, NOTICE_FILES.format(name=blocked_name)
        return False, None

    # -------------------------------------------------- ảnh (chụp màn hình)
    def on_image(self, owner=None):
        status = self._status("SCREEN_CAPTURE")
        if not status["is_governed"]:
            return False, None
        block = status["effective_action"] == "BLOCK"
        action = ACTION_BLOCK if block else "LOGGED"
        self._record("SCREEN_CAPTURE", status, action, owner,
                     {"destination_domain": "Clipboard (anh)", "file_path": None},
                     {"verdict": "BLOCK" if block else "LOG", "reason": "SCREENSHOT_IN_CLIPBOARD"})
        _say("%s anh trong clipboard (tu %s)" % ("CHAN" if block else "GHI NHAN", owner or "PrintScreen"))
        return block, NOTICE_IMAGE

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


def route_clipboard(guard, data, owner):
    """Quyết định nội dung clipboard thuộc loại nào và giao cho đúng hàm xử lý."""
    if data["files"]:
        return guard.on_files(data["files"], owner)
    if is_screenshot(data, owner):
        return guard.on_image(owner)
    if data["text"]:
        return guard.on_text(data["text"], owner)
    return False, None


# ============================================================================
# 2. LỚP WINDOWS: lắng nghe clipboard qua Win32 API (ctypes)
# ============================================================================
CF_TEXT_UNICODE, CF_HDROP, CF_BITMAP, CF_DIB, CF_DIBV5 = 13, 15, 2, 8, 17
WM_CLIPBOARDUPDATE, WM_TIMER = 0x031D, 0x0113
GMEM_MOVEABLE = 0x0002


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

    sig = {  # khai báo kiểu đầy đủ: thiếu restype là handle 64-bit bị cắt -> crash
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
        (user32, "OpenClipboard"): ([w.HWND], w.BOOL),
        (user32, "CloseClipboard"): ([], w.BOOL),
        (user32, "EmptyClipboard"): ([], w.BOOL),
        (user32, "IsClipboardFormatAvailable"): ([w.UINT], w.BOOL),
        (user32, "GetClipboardData"): ([w.UINT], w.HANDLE),
        (user32, "SetClipboardData"): ([w.UINT, w.HANDLE], w.HANDLE),
        (user32, "GetClipboardSequenceNumber"): ([], w.DWORD),
        (user32, "GetClipboardOwner"): ([], w.HWND),
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
    return ctypes, w, user32, kernel32, shell32, WNDPROC, WNDCLASSW


class ClipboardWatcher:
    """Cửa sổ ẩn nhận thông báo WM_CLIPBOARDUPDATE mỗi khi clipboard thay đổi."""

    def __init__(self, guard):
        (self.ct, self.w, self.user32, self.kernel32, self.shell32,
         WNDPROC, WNDCLASSW) = _load_win32()
        self.guard = guard
        self._own_seq = None
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
        self.user32.SetTimer(self.hwnd, 1, TICK_MS, None)

    # -------------------------------------------------- vòng lặp tin nhắn
    def run(self):
        msg = self.w.MSG()
        try:
            while self.user32.GetMessageW(self.ct.byref(msg), None, 0, 0) > 0:
                self.user32.TranslateMessage(self.ct.byref(msg))
                self.user32.DispatchMessageW(self.ct.byref(msg))
        finally:
            self.user32.RemoveClipboardFormatListener(self.hwnd)

    def _wndproc(self, hwnd, msg, wparam, lparam):
        try:
            if msg == WM_CLIPBOARDUPDATE:
                self._on_clipboard_update()
                return 0
            if msg == WM_TIMER:
                self.guard.tick()
                return 0
        except KeyboardInterrupt:
            self.user32.PostQuitMessage(0)
            return 0
        except Exception as e:  # lỗi trong callback không được làm chết agent
            _say("Loi xu ly: %s: %s" % (type(e).__name__, e))
        return self.user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    # -------------------------------------------------- đọc / ghi clipboard
    def _open(self):
        for _ in range(10):  # ứng dụng vừa copy có thể vẫn đang giữ clipboard
            if self.user32.OpenClipboard(self.hwnd):
                return True
            time.sleep(0.02)
        return False

    def _owner_name(self):
        owner = self.user32.GetClipboardOwner()
        if not owner:
            return None
        pid = self.w.DWORD()
        self.user32.GetWindowThreadProcessId(owner, self.ct.byref(pid))
        try:
            return psutil.Process(pid.value).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):
            return None

    def _read(self):
        """Đọc nhanh rồi đóng clipboard ngay, để không giữ chân ứng dụng khác."""
        u = self.user32
        data = {"text": None, "files": [], "image": False}
        if not self._open():
            return None
        try:
            if u.IsClipboardFormatAvailable(CF_HDROP):
                h = u.GetClipboardData(CF_HDROP)
                if h:
                    count = self.shell32.DragQueryFileW(h, 0xFFFFFFFF, None, 0)
                    for i in range(min(count, MAX_FILES_PER_COPY)):
                        n = self.shell32.DragQueryFileW(h, i, None, 0)
                        buf = self.ct.create_unicode_buffer(n + 1)
                        self.shell32.DragQueryFileW(h, i, buf, n + 1)
                        data["files"].append(buf.value)
            if u.IsClipboardFormatAvailable(CF_TEXT_UNICODE):
                h = u.GetClipboardData(CF_TEXT_UNICODE)
                if h:
                    p = self.kernel32.GlobalLock(h)
                    if p:
                        try:
                            size = self.kernel32.GlobalSize(h) // 2
                            data["text"] = self.ct.wstring_at(p, size).split("\0", 1)[0]
                        finally:
                            self.kernel32.GlobalUnlock(h)
            data["image"] = any(u.IsClipboardFormatAvailable(f)
                                for f in (CF_BITMAP, CF_DIB, CF_DIBV5, self.cf_png) if f)
        finally:
            u.CloseClipboard()
        return data

    def _replace_with_notice(self, notice, seq_before):
        """Xoá clipboard, thay bằng dòng thông báo (paste ra sẽ thấy lý do bị chặn)."""
        u, k = self.user32, self.kernel32
        if u.GetClipboardSequenceNumber() != seq_before:
            return  # người dùng đã copy cái khác trong lúc đang quét -> không xoá nhầm
        if not self._open():
            _say("Khong mo duoc clipboard de xoa!")
            return
        try:
            u.EmptyClipboard()
            raw = (notice + "\0").encode("utf-16-le")
            hmem = k.GlobalAlloc(GMEM_MOVEABLE, len(raw))
            p = k.GlobalLock(hmem) if hmem else None
            if p:
                self.ct.memmove(p, raw, len(raw))
                k.GlobalUnlock(hmem)
                if not u.SetClipboardData(CF_TEXT_UNICODE, hmem):
                    k.GlobalFree(hmem)
        finally:
            u.CloseClipboard()
        self._own_seq = u.GetClipboardSequenceNumber()

    def _on_clipboard_update(self):
        seq = self.user32.GetClipboardSequenceNumber()
        if seq == self._own_seq:
            return  # chính agent vừa ghi dòng thông báo -> bỏ qua
        owner = self._owner_name()
        data = self._read()
        if data is None:
            return
        block, notice = route_clipboard(self.guard, data, owner)
        if block:
            self._replace_with_notice(notice, seq)


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
        if data is not None:
            with self._lock:
                self.policies = data.get("applicable_policies", [])

    def _loop(self):
        while True:
            time.sleep(POLICY_REFRESH_SECONDS)
            self._fetch()

    def get(self):
        with self._lock:
            return list(self.policies)

    def report(self, payload):
        self.client.send_report(payload)


def main(argv=None):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    ap = argparse.ArgumentParser(description="DLP Clipboard + Screenshot Agent")
    ap.add_argument("--demo", action="store_true", help="chay thu khong can server")
    ap.add_argument("--monitor", action="store_true", help="(voi --demo) chi ghi nhan, khong chan")
    ap.add_argument("--config", default=str(Path(__file__).with_name("config.ini")))
    args = ap.parse_args(argv)
    if sys.platform != "win32":
        print("clipboard_agent chi chay tren Windows.")
        return 1
    if args.demo:
        policies = demo_policies(args.monitor)
        guard = ClipboardGuard(socket.gethostname(), lambda: policies)
        _say("CHE DO DEMO (%s) - khong ket noi server." % ("chi ghi nhan" if args.monitor else "CHAN"))
    else:
        sp = ServerPolicy(args.config)
        sp.start()
        guard = ClipboardGuard(sp.hostname, sp.get, sp.report)
        _say("Ket noi server voi may %s." % sp.hostname)
    watcher = ClipboardWatcher(guard)
    _say("Dang theo doi clipboard va chup man hinh. Bam Ctrl+C de dung.")
    try:
        watcher.run()
    except KeyboardInterrupt:
        pass
    _say("Da dung.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
