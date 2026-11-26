"""Windows identity and file-context checks for an interactive Curl watcher."""

import ctypes
from ctypes import wintypes
import math
import ntpath
import os
import re
from contextlib import contextmanager
from functools import lru_cache
from typing import NamedTuple


_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_SYNCHRONIZE = 0x00100000
_TOKEN_DUPLICATE = 0x0002
_TOKEN_IMPERSONATE = 0x0004
_TOKEN_QUERY = 0x0008
_HANDLE_FLAG_INHERIT = 0x0001
_TOKEN_PRIMARY = 1
_TOKEN_IMPERSONATION = 2
_SECURITY_IMPERSONATION = 2
_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 258
_ERROR_INSUFFICIENT_BUFFER = 122
_UNIX_EPOCH_FILETIME = 116444736000000000

_TOKEN_USER = 1
_TOKEN_GROUPS = 2
_TOKEN_STATISTICS = 10
_TOKEN_RESTRICTED_SIDS = 11
_TOKEN_SESSION_ID = 12
_TOKEN_ELEVATION = 20
_TOKEN_INTEGRITY_LEVEL = 25
_TOKEN_UI_ACCESS = 26
_TOKEN_IS_APP_CONTAINER = 29
_SE_GROUP_ENABLED = 0x0004
_INTERACTIVE_SID = bytes.fromhex("010100000000000504000000")  # S-1-5-4
_SECURITY_MANDATORY_MEDIUM_RID = 0x2000
_SECURITY_MANDATORY_HIGH_RID = 0x3000
_LOCAL_DRIVE_TYPES = {2, 3, 5, 6}  # Removable, fixed, CD-ROM and RAM disk.
_VOLUME_NAME_NT = 0x2


class OriginUnavailable(RuntimeError):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


class PathContextUnavailable(RuntimeError):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


class LogonScope(NamedTuple):
    user_sid: bytes
    authentication_id: int
    session_id: int
    integrity_level: int


class DriveContext(NamedTuple):
    drive: str
    device: str
    relative_path: str


class _Luid(ctypes.Structure):
    _fields_ = [("low", wintypes.DWORD), ("high", wintypes.LONG)]

    def as_int(self):
        return ((self.high & 0xFFFFFFFF) << 32) | self.low


class _TokenStatistics(ctypes.Structure):
    _fields_ = [
        ("token_id", _Luid),
        ("authentication_id", _Luid),
        ("expiration_time", ctypes.c_int64),
        ("token_type", wintypes.DWORD),
        ("impersonation_level", wintypes.DWORD),
        ("dynamic_charged", wintypes.DWORD),
        ("dynamic_available", wintypes.DWORD),
        ("group_count", wintypes.DWORD),
        ("privilege_count", wintypes.DWORD),
        ("modified_id", _Luid),
    ]


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [("sid", ctypes.c_void_p), ("attributes", wintypes.DWORD)]


class _TokenGroups(ctypes.Structure):
    _fields_ = [("count", wintypes.DWORD), ("first", _SidAndAttributes)]


def _bind(dll, name, result, *arguments):
    api = getattr(dll, name)
    api.argtypes = arguments
    api.restype = result
    return api


class _WindowsAPI:
    def __init__(self):
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        security = ctypes.WinDLL("advapi32", use_last_error=True)
        handle, word, flag = wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL
        handle_ptr, word_ptr = ctypes.POINTER(handle), ctypes.POINTER(word)
        filetime_ptr = ctypes.POINTER(wintypes.FILETIME)
        wide, wide_buffer = wintypes.LPCWSTR, wintypes.LPWSTR

        self.current_process = _bind(kernel, "GetCurrentProcess", handle)
        self._current_thread = _bind(kernel, "GetCurrentThread", handle)
        self._open_process = _bind(kernel, "OpenProcess", handle, word, flag, word)
        self._close = _bind(kernel, "CloseHandle", flag, handle)
        self._times = _bind(kernel, "GetProcessTimes", flag, handle, filetime_ptr,
                            filetime_ptr, filetime_ptr, filetime_ptr)
        self._image_name = _bind(kernel, "QueryFullProcessImageNameW", flag, handle,
                                 word, wide_buffer, word_ptr)
        self._wait = _bind(kernel, "WaitForSingleObject", word, handle, word)
        self._set_handle_info = _bind(kernel, "SetHandleInformation", flag, handle, word, word)
        self.drive_type = _bind(kernel, "GetDriveTypeW", word, wide)
        self._dos_device = _bind(kernel, "QueryDosDeviceW", word, wide, wide_buffer, word)
        self._file_path = _bind(kernel, "GetFinalPathNameByHandleW", word, handle,
                                wide_buffer, word, word)
        self._process_token = _bind(security, "OpenProcessToken", flag, handle, word, handle_ptr)
        self._thread_token = _bind(security, "OpenThreadToken", flag, handle, word,
                                   flag, handle_ptr)
        self._get_token = _bind(security, "GetTokenInformation", flag, handle, word,
                                 ctypes.c_void_p, word, word_ptr)
        self._duplicate_token = _bind(security, "DuplicateTokenEx", flag, handle,
                                     word, ctypes.c_void_p, word, word, handle_ptr)
        self._sid_length = _bind(security, "GetLengthSid", word, ctypes.c_void_p)
        self._impersonate = _bind(security, "ImpersonateLoggedOnUser", flag, handle)
        self.revert = _bind(security, "RevertToSelf", flag)

    def open_process(self, pid):
        process = self._open_process(_PROCESS_QUERY_LIMITED_INFORMATION | _SYNCHRONIZE, False, pid)
        if not process:
            raise ctypes.WinError(ctypes.get_last_error())
        return process

    def close(self, handle):
        self._close(handle)

    def disable_inheritance(self, handle):
        if not self._set_handle_info(handle, _HANDLE_FLAG_INHERIT, 0):
            raise ctypes.WinError(ctypes.get_last_error())

    def creation_time(self, handle):
        created, exited, kernel, user = (wintypes.FILETIME() for _ in range(4))
        if not self._times(handle, ctypes.byref(created), ctypes.byref(exited),
                           ctypes.byref(kernel), ctypes.byref(user)):
            raise ctypes.WinError(ctypes.get_last_error())
        return (created.dwHighDateTime << 32) | created.dwLowDateTime

    def image_name(self, handle):
        buffer = ctypes.create_unicode_buffer(32768)
        length = wintypes.DWORD(len(buffer))
        if not self._image_name(handle, 0, buffer, ctypes.byref(length)):
            raise ctypes.WinError(ctypes.get_last_error())
        return buffer.value

    def is_running(self, handle):
        result = self._wait(handle, 0)
        if result == _WAIT_TIMEOUT:
            return True
        if result == _WAIT_OBJECT_0:
            return False
        raise ctypes.WinError(ctypes.get_last_error())

    def open_process_token(self, process, *, duplicate=False):
        token = wintypes.HANDLE()
        access = _TOKEN_QUERY | (_TOKEN_DUPLICATE if duplicate else 0)
        if not self._process_token(process, access, ctypes.byref(token)):
            raise ctypes.WinError(ctypes.get_last_error())
        return token.value

    def open_thread_token(self):
        token = wintypes.HANDLE()
        if not self._thread_token(self._current_thread(), _TOKEN_QUERY, True, ctypes.byref(token)):
            raise ctypes.WinError(ctypes.get_last_error())
        return token.value

    def _token_buffer(self, token, kind):
        needed = wintypes.DWORD()
        if self._get_token(token, kind, None, 0, ctypes.byref(needed)):
            raise OSError("Unexpected empty token information")
        error = ctypes.get_last_error()
        if error != _ERROR_INSUFFICIENT_BUFFER or not needed.value:
            raise ctypes.WinError(error)
        buffer = ctypes.create_string_buffer(needed.value)
        if not self._get_token(token, kind, buffer, len(buffer), ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())
        return buffer

    def _token_word(self, token, kind):
        value = wintypes.DWORD()
        returned = wintypes.DWORD()
        if not self._get_token(token, kind, ctypes.byref(value), ctypes.sizeof(value),
                               ctypes.byref(returned)):
            raise ctypes.WinError(ctypes.get_last_error())
        return value.value

    def _sid_bytes(self, sid):
        return ctypes.string_at(sid, self._sid_length(sid))

    def _token_sid(self, token, kind):
        buffer = self._token_buffer(token, kind)
        sid = _SidAndAttributes.from_buffer_copy(buffer).sid
        return self._sid_bytes(sid)

    def _is_interactive(self, token):
        buffer = self._token_buffer(token, _TOKEN_GROUPS)
        count = wintypes.DWORD.from_buffer_copy(buffer).value
        groups = (_SidAndAttributes * count).from_buffer(buffer, _TokenGroups.first.offset)
        return any(group.attributes & _SE_GROUP_ENABLED and self._sid_bytes(group.sid) == _INTERACTIVE_SID
                   for group in groups)

    def token_context(self, token, *, impersonation=False):
        stats = _TokenStatistics.from_buffer_copy(self._token_buffer(token, _TOKEN_STATISTICS))
        if stats.token_type != (_TOKEN_IMPERSONATION if impersonation else _TOKEN_PRIMARY):
            raise OriginUnavailable("TOKEN_CONTEXT_UNSUPPORTED")
        if impersonation and stats.impersonation_level != _SECURITY_IMPERSONATION:
            raise OriginUnavailable("TOKEN_CONTEXT_UNSUPPORTED")
        # The final subauthority of the mandatory label SID is the integrity RID.
        integrity_sid = self._token_sid(token, _TOKEN_INTEGRITY_LEVEL)
        integrity_level = int.from_bytes(integrity_sid[-4:], "little")
        session_id = self._token_word(token, _TOKEN_SESSION_ID)
        if (not session_id or
                not _SECURITY_MANDATORY_MEDIUM_RID <= integrity_level < _SECURITY_MANDATORY_HIGH_RID or
                self._token_word(token, _TOKEN_ELEVATION) or
                self._token_word(token, _TOKEN_UI_ACCESS) or
                self._token_word(token, _TOKEN_IS_APP_CONTAINER) or
                wintypes.DWORD.from_buffer_copy(self._token_buffer(token, _TOKEN_RESTRICTED_SIDS)).value or
                not self._is_interactive(token)):
            raise OriginUnavailable("TOKEN_CONTEXT_UNSUPPORTED")
        scope = LogonScope(self._token_sid(token, _TOKEN_USER), stats.authentication_id.as_int(),
                           session_id, integrity_level)
        return scope, stats.token_id.as_int()

    def duplicate_origin_token(self, token):
        duplicate = wintypes.HANDLE()
        if not self._duplicate_token(token, _TOKEN_QUERY | _TOKEN_IMPERSONATE, None,
                                     _SECURITY_IMPERSONATION, _TOKEN_IMPERSONATION,
                                     ctypes.byref(duplicate)):
            raise ctypes.WinError(ctypes.get_last_error())
        return duplicate.value

    def impersonate(self, token):
        if not self._impersonate(token):
            raise ctypes.WinError(ctypes.get_last_error())

    def device_for_drive(self, drive):
        devices = ctypes.create_unicode_buffer(32768)
        if not self._dos_device(drive, devices, len(devices)):
            raise ctypes.WinError(ctypes.get_last_error())
        return devices.value  # QueryDosDevice returns the active mapping first.

    def file_device_path(self, stream):
        import msvcrt

        path = ctypes.create_unicode_buffer(32768)
        size = self._file_path(msvcrt.get_osfhandle(stream.fileno()), path, len(path), _VOLUME_NAME_NT)
        if not size:
            raise ctypes.WinError(ctypes.get_last_error())
        if size >= len(path):
            raise OSError("File device path exceeds the supported length")
        return path.value


@lru_cache(maxsize=1)
def _api():
    if os.name != "nt":
        raise OSError("Windows identity is unavailable")
    return _WindowsAPI()


class OriginProcess:
    """Own a live process reference and the original noninheritable worker token."""

    def __init__(self, api, handle, creation_filetime, token_handle):
        self._api = api
        self._handle = handle
        self.creation_filetime = creation_filetime
        self.token_handle = token_handle

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def is_running(self):
        return self._handle is not None and self._api.is_running(self._handle)

    def close_token(self):
        if self.token_handle is not None:
            self._api.close(self.token_handle)
            self.token_handle = None

    def close(self):
        self.close_token()
        if self._handle is not None:
            self._api.close(self._handle)
            self._handle = None


def watcher_scope():
    try:
        api = _api()
        token = api.open_process_token(api.current_process())
        try:
            scope, _ = api.token_context(token)
            return scope
        finally:
            api.close(token)
    except (OSError, OriginUnavailable):
        raise OriginUnavailable("WATCHER_CONTEXT_UNSUPPORTED") from None


def open_origin(pid, observed_create_time, scope):
    """Pin the OS process and verify its identity before reading untrusted metadata."""
    try:
        api = _api()
        process = api.open_process(pid)
    except OSError:
        raise OriginUnavailable("PROCESS_IDENTITY_UNAVAILABLE") from None
    worker_token = None
    try:
        created = api.creation_time(process)
        unix_seconds = (created - _UNIX_EPOCH_FILETIME) / 10_000_000
        # psutil exposes a float, which can round the native timestamp by one ULP.
        if (not math.isfinite(observed_create_time) or
                abs(unix_seconds - observed_create_time) > math.ulp(unix_seconds) or
                ntpath.basename(api.image_name(process)).casefold() != "curl.exe" or
                not api.is_running(process)):
            raise OriginUnavailable("PROCESS_IDENTITY_UNAVAILABLE")
        try:
            token = api.open_process_token(process, duplicate=True)
            try:
                target_scope, _ = api.token_context(token)
                if target_scope != scope:
                    raise OriginUnavailable("TOKEN_CONTEXT_UNSUPPORTED")
                worker_token = api.duplicate_origin_token(token)
            finally:
                api.close(token)
        except OSError:
            raise OriginUnavailable("ORIGIN_TOKEN_UNAVAILABLE") from None
        if not api.is_running(process):
            raise OriginUnavailable("PROCESS_IDENTITY_UNAVAILABLE")
        origin = OriginProcess(api, process, created, worker_token)
        process = None  # Ownership transferred only after all checks succeed.
        worker_token = None
        return origin
    except OSError:
        raise OriginUnavailable("PROCESS_IDENTITY_UNAVAILABLE") from None
    finally:
        if worker_token is not None:
            api.close(worker_token)
        if process is not None:
            api.close(process)


@contextmanager
def impersonate_origin(token_handle):
    """Consume the explicitly inherited token in the actual inspection process."""
    try:
        api = _api()
    except OSError:
        raise OriginUnavailable("ORIGIN_IMPERSONATION_UNAVAILABLE") from None
    scoped = False
    try:
        try:
            api.disable_inheritance(token_handle)
            expected_scope, expected_id = api.token_context(token_handle, impersonation=True)
            if expected_scope != watcher_scope():
                raise OriginUnavailable("TOKEN_CONTEXT_UNSUPPORTED")
            api.impersonate(token_handle)
            scoped = True
            thread_token = api.open_thread_token()
            try:
                active_scope, active_id = api.token_context(thread_token, impersonation=True)
            finally:
                api.close(thread_token)
            if (active_scope, active_id) != (expected_scope, expected_id):
                raise OriginUnavailable("TOKEN_CONTEXT_UNSUPPORTED")
        except (OSError, OriginUnavailable):
            raise OriginUnavailable("ORIGIN_IMPERSONATION_UNAVAILABLE") from None

        yield active_scope
    finally:
        if scoped and not api.revert():
            # The rest of this worker must not run under an unexpected token.
            os._exit(1)
        api.close(token_handle)


def verify_drive(path):
    """Require a direct local drive mapping, in the impersonated logon's namespace."""
    drive, relative_path = ntpath.splitdrive(os.fspath(path))
    if not re.fullmatch(r"[A-Za-z]:", drive) or not relative_path.startswith("\\"):
        raise PathContextUnavailable("UNVERIFIED_SOURCE_PATH")
    try:
        api = _api()
        if api.drive_type(drive + "\\") not in _LOCAL_DRIVE_TYPES:
            raise PathContextUnavailable("NON_LOCAL_SOURCE_VOLUME")
        device = api.device_for_drive(drive)
    except OSError:
        raise PathContextUnavailable("UNVERIFIED_SOURCE_PATH") from None
    # SUBST mappings target another DOS path. A direct volume is a single NT device.
    if not re.fullmatch(r"\\Device\\[^\\]+", device, flags=re.IGNORECASE):
        raise PathContextUnavailable("UNSUPPORTED_SOURCE_ALIAS")
    return DriveContext(drive, device, relative_path)


def verify_file_volume(stream, drive):
    """Check the already-opened handle against the verified volume and file path."""
    try:
        api = _api()
        resolved = api.file_device_path(stream)
        live_device = api.device_for_drive(drive.drive)
    except OSError:
        raise PathContextUnavailable("UNVERIFIED_SOURCE_PATH") from None
    if (ntpath.normcase(live_device) != ntpath.normcase(drive.device) or
            ntpath.normcase(resolved) != ntpath.normcase(drive.device + drive.relative_path)):
        raise PathContextUnavailable("UNSUPPORTED_SOURCE_ALIAS")
