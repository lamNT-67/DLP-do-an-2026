"""Windows desktop resources used only by the limited-user Curl task."""

import ctypes
import stat
import threading
from contextlib import contextmanager
from ctypes import wintypes as w
from pathlib import Path

from curl_windows import _bind


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [("length", w.DWORD), ("descriptor", w.LPVOID), ("inherit", w.BOOL)]


def _sid_text(sid):
    # Input is the binary TOKEN_USER SID obtained from Windows.
    if len(sid) < 8 or sid[0] != 1 or not sid[1] or len(sid) != 8 + 4 * sid[1]:
        raise ValueError("Invalid watcher SID")
    values = [int.from_bytes(sid[2:8], "big")]
    values.extend(int.from_bytes(sid[i:i + 4], "little") for i in range(8, len(sid), 4))
    return "S-1-" + "-".join(map(str, values))


def _check_local_path(path, *, directory):
    info = path.lstat()
    if info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise OSError("A managed journal path is redirected")
    if directory:
        if not stat.S_ISDIR(info.st_mode):
            raise OSError("Expected a journal directory")
    elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise OSError("Expected a regular journal file with a single hard link")


def _validate_acl(api, free, path, sid, *, directory):
    owner, acl, descriptor = w.LPVOID(), w.LPVOID(), w.LPVOID()
    get_security = _bind(api, "GetNamedSecurityInfoW", w.DWORD, w.LPCWSTR, ctypes.c_int, w.DWORD,
                         ctypes.POINTER(w.LPVOID), w.LPVOID, ctypes.POINTER(w.LPVOID),
                         w.LPVOID, ctypes.POINTER(w.LPVOID))
    error = get_security(str(path), 1, 5, ctypes.byref(owner), None, ctypes.byref(acl),
                         None, ctypes.byref(descriptor))  # SE_FILE_OBJECT, OWNER | DACL
    if error:
        raise ctypes.WinError(error)
    try:
        sid_len = _bind(api, "GetLengthSid", w.DWORD, w.LPVOID)
        get_ace = _bind(api, "GetAce", w.BOOL, w.LPVOID, w.DWORD, ctypes.POINTER(w.LPVOID))
        # SYSTEM and BUILTIN\Administrators are the only other permitted trustees.
        trusted = {sid, bytes.fromhex("010100000000000512000000"),
                   bytes.fromhex("01020000000000052000000020020000")}
        if not owner.value or ctypes.string_at(owner, sid_len(owner)) not in trusted or not acl.value:
            raise OSError("Managed journals require a private owner and DACL")
        # ACL.AceCount is a WORD at offset 4. Allow only simple effective full-access
        # ACEs. Files inherit them and directories must pass them on to new journals.
        count = w.WORD.from_address(acl.value + 4).value
        seen = set()
        for index in range(count):
            ace = w.LPVOID()
            if not get_ace(acl, index, ctypes.byref(ace)):
                raise ctypes.WinError(ctypes.get_last_error())
            kind, flags = ctypes.string_at(ace, 2)
            if kind != 0 or flags & 0x0c or (directory and flags & 3 != 3):
                raise OSError("Unexpected managed journal access rule")
            trustee = ace.value + 8  # ACCESS_ALLOWED_ACE.SidStart
            principal = ctypes.string_at(trustee, sid_len(trustee))
            if principal not in trusted or w.DWORD.from_address(ace.value + 4).value != 0x1f01ff:
                raise OSError("Managed journal grants unexpected access")
            seen.add(principal)
        if sid not in seen:
            raise OSError("Watcher cannot own its journals")
    finally:
        free(descriptor)


def private_journal_directory(scope):
    """Use the profile's local known folder and create the private ACL atomically."""
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    known = _bind(shell, "SHGetFolderPathW", ctypes.c_long, w.HWND, ctypes.c_int,
                  w.HANDLE, w.DWORD, w.LPWSTR)
    buffer = ctypes.create_unicode_buffer(260)
    if known(None, 0x1c, None, 0, buffer) != 0:  # CSIDL_LOCAL_APPDATA of this token
        raise OSError("Local AppData unavailable")
    parent = Path(buffer.value)
    drive_type = _bind(kernel, "GetDriveTypeW", w.UINT, w.LPCWSTR)
    if not parent.is_absolute() or len(parent.drive) != 2 or drive_type(parent.anchor) != 3:
        raise OSError("Managed journals require a fixed local volume")
    for ancestor in (*reversed(parent.parents), parent):
        _check_local_path(ancestor, directory=True)
    path = parent / "DLP-Curl"
    sid = scope.user_sid
    sddl = f"D:P(A;OICI;FA;;;{_sid_text(sid)})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
    convert = _bind(security, "ConvertStringSecurityDescriptorToSecurityDescriptorW", w.BOOL,
                    w.LPCWSTR, w.DWORD, ctypes.POINTER(w.LPVOID), w.LPVOID)
    free = _bind(kernel, "LocalFree", w.HANDLE, w.HANDLE)
    create = _bind(kernel, "CreateDirectoryW", w.BOOL, w.LPCWSTR, ctypes.POINTER(_SecurityAttributes))
    descriptor = w.LPVOID()
    if not convert(sddl, 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        attributes = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
        if not create(str(path), ctypes.byref(attributes)) and ctypes.get_last_error() != 183:
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        free(descriptor)
    _check_local_path(path, directory=True)
    _validate_acl(security, free, path, sid, directory=True)
    for name in ("dlp_events.log", "curl_delivery.log"):
        try:
            _check_local_path(path / name, directory=False)
        except FileNotFoundError:
            continue
        _validate_acl(security, free, path / name, sid, directory=False)
    return path


@contextmanager
def session_end_notifications(stop):
    """A hidden top-level window can receive actual interactive logoff broadcasts."""
    user = ctypes.WinDLL("user32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    wndproc = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, w.HWND, w.UINT, w.WPARAM, w.LPARAM)

    class WindowClass(ctypes.Structure):
        _fields_ = [("style", w.UINT), ("proc", wndproc), ("class_extra", ctypes.c_int),
                    ("window_extra", ctypes.c_int), ("instance", w.HINSTANCE), ("icon", w.HICON),
                    ("cursor", w.HANDLE), ("background", w.HBRUSH), ("menu", w.LPCWSTR),
                    ("name", w.LPCWSTR)]

    register = _bind(user, "RegisterClassW", w.ATOM, ctypes.POINTER(WindowClass))
    unregister = _bind(user, "UnregisterClassW", w.BOOL, w.LPCWSTR, w.HINSTANCE)
    create = _bind(user, "CreateWindowExW", w.HWND, w.DWORD, w.LPCWSTR, w.LPCWSTR, w.DWORD,
                   ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, w.HWND, w.HMENU,
                   w.HINSTANCE, w.LPVOID)
    default = _bind(user, "DefWindowProcW", ctypes.c_ssize_t, w.HWND, w.UINT, w.WPARAM, w.LPARAM)
    get = _bind(user, "GetMessageW", ctypes.c_int, ctypes.POINTER(w.MSG), w.HWND, w.UINT, w.UINT)
    dispatch = _bind(user, "DispatchMessageW", ctypes.c_ssize_t, ctypes.POINTER(w.MSG))
    post = _bind(user, "PostMessageW", w.BOOL, w.HWND, w.UINT, w.WPARAM, w.LPARAM)
    quit_loop = _bind(user, "PostQuitMessage", None, ctypes.c_int)
    destroy = _bind(user, "DestroyWindow", w.BOOL, w.HWND)
    module = _bind(kernel, "GetModuleHandleW", w.HMODULE, w.LPCWSTR)(None)
    ready, finished = threading.Event(), threading.Event()
    hwnd = None

    @wndproc
    def callback(window, message, wparam, lparam):
        if message == 0x0011:  # WM_QUERYENDSESSION, the user can still cancel
            return 1
        if message == 0x0016:  # WM_ENDSESSION
            if wparam:
                stop.set()
                finished.wait(12)  # Windows can terminate earlier. Receipt remains authoritative.
            return 0
        if message == 0x8001:  # private WM_APP message from context exit
            quit_loop(0)
            return 0
        return default(window, message, wparam, lparam)

    def listen():
        nonlocal hwnd
        wc = WindowClass(proc=callback, instance=module, name="DLPCurlAgentSessionEnd")
        atom = register(ctypes.byref(wc))
        try:
            if atom:
                hwnd = create(0, wc.name, "", 0, 0, 0, 0, 0, None, None, module, None)
            ready.set()
            if hwnd:
                msg = w.MSG()
                while get(ctypes.byref(msg), None, 0, 0) > 0:
                    dispatch(ctypes.byref(msg))
        finally:
            stop.set()
            ready.set()
            if hwnd:
                destroy(hwnd)
            if atom:
                unregister(wc.name, module)

    listener = threading.Thread(target=listen, name="curl-session-end", daemon=True)
    listener.start()
    try:
        if not ready.wait(5) or not hwnd:
            raise OSError("Could not receive session end notifications")
        yield
    finally:
        finished.set()
        if hwnd:
            post(hwnd, 0x8001, 0, 0)
        listener.join(2)
