import json
import os
import datetime
from pathlib import Path

LOG_DIR = Path(os.environ.get("DLP_LOG_DIR", "./logs"))
LOG_FILE = LOG_DIR / "dlp_events.log"
CLIPBOARD_DELIVERY_FILE = LOG_DIR / "clipboard_delivery.log"


if os.name == "nt":
    import ctypes
    import msvcrt
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _create_file = _kernel32.CreateFileW
    _create_file.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                             wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    _create_file.restype = wintypes.HANDLE
    _close_handle = _kernel32.CloseHandle
    _close_handle.argtypes = (wintypes.HANDLE,)
    _close_handle.restype = wintypes.BOOL

    def _open_append(path):
        # An append-only handle lets Windows position each write at EOF across processes.
        FILE_APPEND_DATA = 0x0004
        FILE_SHARE_READ_WRITE = 0x0003
        OPEN_ALWAYS = 4
        FILE_ATTRIBUTE_NORMAL = 0x0080
        handle = _create_file(str(path), FILE_APPEND_DATA, FILE_SHARE_READ_WRITE, None,
                              OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return msvcrt.open_osfhandle(handle, os.O_WRONLY | os.O_BINARY | os.O_NOINHERIT)
        except OSError:
            _close_handle(handle)
            raise
else:
    def _open_append(path):
        return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o666)


def _now_iso():
    return datetime.datetime.now().astimezone().isoformat()


def _append_json(path, record, *, durable):
    line = json.dumps(record, ensure_ascii=False) + os.linesep
    data = line.encode("utf-8", errors="backslashreplace")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = _open_append(path)
    try:
        if os.write(fd, data) != len(data):
            raise OSError("Incomplete log write")
        if durable:
            os.fsync(fd)
    finally:
        os.close(fd)


def write_log_event(hostname, agent_module, exit_point_type, event_type, policy_state,
                     source, target, content_inspection, action_taken, reported_to_server, *,
                     event_id=None, policy_id=None, report_configured=None, durable=False):
    event = {
        "timestamp": _now_iso(), "hostname": hostname, "agent_module": agent_module,
        "exit_point_type": exit_point_type, "event_type": event_type,
        "policy_state": policy_state, "source": source, "target": target,
        "content_inspection": content_inspection, "action_taken": action_taken,
        "reported_to_server": reported_to_server,
    }
    if event_id is not None:
        event.update(event_id=event_id, policy_id=policy_id, report_configured=report_configured)
    _append_json(LOG_FILE, event, durable=durable)
    return event


def write_clipboard_delivery_status(event_id, status, *, server_log_id=None):
    record = {
        "timestamp": _now_iso(), "event_id": event_id, "status": status,
        "reported_to_server": status == "ACKNOWLEDGED",
    }
    if server_log_id is not None:
        record["server_log_id"] = server_log_id
    _append_json(CLIPBOARD_DELIVERY_FILE, record, durable=True)
