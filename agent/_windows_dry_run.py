"""Handle-relative fixture scans and temporary demo fixtures on Windows."""

from contextlib import ExitStack, contextmanager
import ctypes as ct
from ctypes import wintypes as wt
import msvcrt
import os
import re
import stat
import struct
from threading import Lock
import uuid
import weakref


_FILE_READ_DATA = _FILE_LIST_DIRECTORY = 0x0001
_FILE_WRITE_DATA = 0x0002
_FILE_TRAVERSE = 0x0020
_FILE_READ_ATTRIBUTES = 0x0080
_DELETE = 0x00010000
_SYNCHRONIZE = 0x00100000
_DIRECTORY_ACCESS = _FILE_LIST_DIRECTORY | _FILE_TRAVERSE | _FILE_READ_ATTRIBUTES
_SHARE_READ, _SHARE_WRITE, _SHARE_DELETE = 1, 2, 4
_SHARE_ALL = _SHARE_READ | _SHARE_WRITE | _SHARE_DELETE
_FILE_DIRECTORY_FILE, _FILE_NON_DIRECTORY_FILE = 0x0001, 0x0040
_FILE_SYNCHRONOUS_IO_NONALERT = 0x0020
_FILE_DELETE_ON_CLOSE = 0x00001000
_OPEN_REPARSE_POINT = 0x00200000
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_OPEN, _FILE_CREATE, _OPEN_EXISTING = 1, 2, 3
_OBJ_CASE_INSENSITIVE = 0x0040
_INVALID_HANDLE = ct.c_void_p(-1).value
_DIR_ATTRIBUTE = stat.FILE_ATTRIBUTE_DIRECTORY
_REPARSE_ATTRIBUTE = stat.FILE_ATTRIBUTE_REPARSE_POINT
_FILE_BASIC_INFO, _FILE_STANDARD_INFO, _FILE_ID_INFO = 0, 1, 18
_FILE_FULL_DIR_INFO, _FILE_FULL_DIR_RESTART_INFO = 14, 15
_ERROR_NO_MORE_FILES = 18
_DRIVE_FIXED = 3
_IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400
_BUS_TYPE_USB = 7
_LAST_KNOWN_BUS_TYPE = 20  # BusTypeNvmeof


class _UnicodeString(ct.Structure):
    _fields_ = [("length", wt.USHORT), ("maximum_length", wt.USHORT),
                ("buffer", wt.LPWSTR)]


class _ObjectAttributes(ct.Structure):
    _fields_ = [("length", wt.ULONG), ("root", wt.HANDLE),
                ("name", ct.POINTER(_UnicodeString)), ("attributes", wt.ULONG),
                ("security_descriptor", wt.LPVOID), ("security_qos", wt.LPVOID)]


class _IoStatusBlock(ct.Structure):
    # The first member is a union of NTSTATUS and a pointer.
    _fields_ = [("status_or_pointer", wt.LPVOID), ("information", ct.c_size_t)]


class _BasicInfo(ct.Structure):
    _fields_ = [("creation_time", ct.c_int64), ("access_time", ct.c_int64),
                ("write_time", ct.c_int64), ("change_time", ct.c_int64),
                ("attributes", wt.DWORD)]


class _StandardInfo(ct.Structure):
    _fields_ = [("allocation_size", ct.c_int64), ("size", ct.c_int64),
                ("links", wt.DWORD), ("delete_pending", wt.BOOLEAN), ("directory", wt.BOOLEAN)]


class _IdInfo(ct.Structure):
    _fields_ = [("volume", ct.c_uint64), ("file_id", ct.c_ubyte * 16)]


class _FullDirInfo(ct.Structure):
    _fields_ = [("next_offset", wt.ULONG), ("file_index", wt.ULONG),
                ("creation_time", ct.c_int64), ("access_time", ct.c_int64),
                ("write_time", ct.c_int64), ("change_time", ct.c_int64),
                ("size", ct.c_int64), ("allocation_size", ct.c_int64),
                ("attributes", wt.ULONG), ("name_length", wt.ULONG),
                ("ea_size", wt.ULONG), ("name", wt.WCHAR * 1)]


def _bind(dll, name, restype, *argtypes):
    function = getattr(dll, name)
    function.restype = restype
    function.argtypes = argtypes
    return function


_kernel32 = ct.WinDLL("kernel32", use_last_error=True)
_ntdll = ct.WinDLL("ntdll")
_create_file = _bind(_kernel32, "CreateFileW", wt.HANDLE, wt.LPCWSTR, wt.DWORD, wt.DWORD,
                     wt.LPVOID, wt.DWORD, wt.DWORD, wt.HANDLE)
_close = _bind(_kernel32, "CloseHandle", wt.BOOL, wt.HANDLE)
_get_info = _bind(_kernel32, "GetFileInformationByHandleEx", wt.BOOL,
                  wt.HANDLE, ct.c_int, wt.LPVOID, wt.DWORD)
_get_volume_name = _bind(_kernel32, "GetVolumeNameForVolumeMountPointW", wt.BOOL,
                         wt.LPCWSTR, wt.LPWSTR, wt.DWORD)
_get_drive_type = _bind(_kernel32, "GetDriveTypeW", wt.UINT, wt.LPCWSTR)
_get_volume_info = _bind(_kernel32, "GetVolumeInformationByHandleW", wt.BOOL, wt.HANDLE,
                         wt.LPWSTR, wt.DWORD, wt.LPVOID, wt.LPVOID, wt.LPVOID, wt.LPWSTR, wt.DWORD)
_device_control = _bind(_kernel32, "DeviceIoControl", wt.BOOL, wt.HANDLE, wt.DWORD, wt.LPVOID,
                        wt.DWORD, wt.LPVOID, wt.DWORD, ct.POINTER(wt.DWORD), wt.LPVOID)
_nt_create_file = _bind(_ntdll, "NtCreateFile", wt.LONG, ct.POINTER(wt.HANDLE), wt.ULONG,
                        ct.POINTER(_ObjectAttributes), ct.POINTER(_IoStatusBlock), wt.LPVOID,
                        wt.ULONG, wt.ULONG, wt.ULONG, wt.ULONG, wt.LPVOID, wt.ULONG)
_to_winerror = _bind(_ntdll, "RtlNtStatusToDosError", wt.ULONG, wt.LONG)


def _open_absolute(path, access, flags=0):
    handle = _create_file(path, access, _SHARE_ALL, None, _OPEN_EXISTING, flags, None)
    if handle == _INVALID_HANDLE:
        raise ct.WinError(ct.get_last_error())
    return handle


def local_fixture_volume(anchor):
    """Resolve a drive root through Mount Manager and verify its storage metadata."""
    if not re.fullmatch(r"[A-Za-z]:\\", anchor):
        raise ValueError("Dry-run requires a local fixed NTFS volume for synthetic fixtures")
    volume = ct.create_unicode_buffer(64)
    if not _get_volume_name(anchor, volume, len(volume)):
        raise ct.WinError(ct.get_last_error())
    if _get_drive_type(volume.value) != _DRIVE_FIXED:
        raise ValueError("Dry-run requires a local fixed NTFS volume for synthetic fixtures")

    # A USB disk can report DRIVE_FIXED. Query the volume's storage descriptor
    # with zero access. This obtains device metadata without enumerating files.
    with ExitStack() as stack:
        handle = _open_absolute(volume.value.rstrip("\\"), 0)
        stack.callback(_close, handle)
        query = struct.pack("<III", 0, 0, 0)  # StorageDeviceProperty, PropertyStandardQuery
        response = ct.create_string_buffer(4096)
        returned = wt.DWORD()
        if not _device_control(handle, _IOCTL_STORAGE_QUERY_PROPERTY, query, len(query),
                               response, len(response), ct.byref(returned), None):
            raise ct.WinError(ct.get_last_error())
        # STORAGE_DEVICE_DESCRIPTOR.BusType is a 32-bit enum at byte offset 28.
        if returned.value < 32:
            raise OSError("Dry-run could not verify the fixture volume's storage bus")
        bus, = struct.unpack_from("<I", response, 28)
        if not 1 <= bus <= _LAST_KNOWN_BUS_TYPE or bus == _BUS_TYPE_USB:
            raise ValueError("Dry-run requires a known non-USB fixture volume")
    return volume.value


def _is_component(name):
    return (bool(name) and name not in (".", "..") and not name.endswith((" ", "."))
            and not any(character in name for character in "\\/:\0"))


def _open_relative(parent, name, access, share, *, directory, create_temporary=False):
    """Open exactly one component, treating a reparse point as the object itself."""
    if not _is_component(name):
        raise ValueError("Dry-run requires a single ordinary path component")
    # Use the byte length of the UTF-16 name, including surrogate pairs.
    raw_name = name.encode("utf-16-le", errors="surrogatepass")
    if len(raw_name) > 65532:
        raise ValueError("Dry-run path component is too long")
    buffer = ct.create_string_buffer(raw_name + b"\0\0")
    native_name = _UnicodeString(len(raw_name), len(raw_name) + 2, ct.cast(buffer, wt.LPWSTR))
    attrs = _ObjectAttributes(ct.sizeof(_ObjectAttributes), parent, ct.pointer(native_name),
                              _OBJ_CASE_INSENSITIVE if directory else 0, None, None)
    flags = _FILE_DIRECTORY_FILE if directory else _FILE_NON_DIRECTORY_FILE
    if create_temporary:
        access |= _DELETE
        flags |= _FILE_DELETE_ON_CLOSE
    handle = wt.HANDLE()
    status = _nt_create_file(ct.byref(handle), access | _SYNCHRONIZE, ct.byref(attrs),
                             ct.byref(_IoStatusBlock()), None, 0, share,
                             _FILE_CREATE if create_temporary else _FILE_OPEN,
                             flags | _FILE_SYNCHRONOUS_IO_NONALERT | _OPEN_REPARSE_POINT, None, 0)
    if status < 0:
        raise ct.WinError(_to_winerror(status))
    return handle.value


def _query(handle, info_type, structure):
    result = structure()
    if not _get_info(handle, info_type, ct.byref(result), ct.sizeof(result)):
        raise ct.WinError(ct.get_last_error())
    return result


def _identity(handle):
    info = _query(handle, _FILE_ID_INFO, _IdInfo)
    if not any(info.file_id):
        raise OSError("Dry-run could not identify the opened filesystem object")
    return info.volume, bytes(info.file_id)


def _require_directory(handle):
    attributes = _query(handle, _FILE_BASIC_INFO, _BasicInfo).attributes
    if not attributes & _DIR_ATTRIBUTE or attributes & _REPARSE_ATTRIBUTE:
        raise ValueError("Dry-run directory must not traverse links or reparse points")


def _file_version(handle):
    basic = _query(handle, _FILE_BASIC_INFO, _BasicInfo)
    if basic.attributes & (_DIR_ATTRIBUTE | _REPARSE_ATTRIBUTE):
        return None
    standard = _query(handle, _FILE_STANDARD_INFO, _StandardInfo)
    # Multiple hard links could alias a file outside the fixture directory.
    if standard.directory or standard.delete_pending or standard.links != 1:
        return None
    return (*_identity(handle), standard.size, basic.write_time, basic.change_time)


@contextmanager
def _binary_stream(handle, mode="rb"):
    """Own the native handle until the CRT takes it, then own the descriptor."""
    access = os.O_RDONLY if mode == "rb" else os.O_WRONLY
    try:
        fd = msvcrt.open_osfhandle(handle, access | os.O_BINARY | os.O_NOINHERIT)
    except BaseException:
        _close(handle)
        raise
    try:
        with os.fdopen(fd, mode, closefd=False) as stream:
            yield stream
    finally:
        os.close(fd)


class EntryChanged(Exception):
    """The opened file cannot be inspected as the observed version."""


class DirectoryScan:
    """Borrow a validated directory handle for one scan scope."""

    def __init__(self, handle):
        self._handle = handle
        self._lock = Lock()

    def _end(self):
        with self._lock:
            self._handle = None

    def _active_handle(self):
        if self._handle is None:
            raise ValueError("Dry-run directory scan is closed")
        return self._handle

    def _open_child(self, name, access, share):
        with self._lock:
            return _open_relative(self._active_handle(), name, access, share, directory=False)

    def names(self, *, include_other=False):
        # Use a buffer with the documented eight-byte alignment.
        buffer = (ct.c_uint64 * 8192)()
        capacity = ct.sizeof(buffer)
        info_type = _FILE_FULL_DIR_RESTART_INFO
        while True:
            with self._lock:
                if not _get_info(self._active_handle(), info_type, buffer, capacity):
                    error = ct.get_last_error()
                    break
            info_type = _FILE_FULL_DIR_INFO
            offset = 0
            while True:
                if capacity - offset < ct.sizeof(_FullDirInfo):
                    raise OSError("Invalid dry-run directory enumeration")
                entry = _FullDirInfo.from_buffer(buffer, offset)
                start = offset + _FullDirInfo.name.offset
                end = start + entry.name_length
                following = offset + entry.next_offset if entry.next_offset else capacity
                if not entry.name_length or entry.name_length % 2 or not end <= following <= capacity:
                    raise OSError("Invalid dry-run directory enumeration")
                if include_other or not entry.attributes & (_DIR_ATTRIBUTE | _REPARSE_ATTRIBUTE):
                    name = ct.string_at(ct.addressof(buffer) + start, entry.name_length)
                    name = name.decode("utf-16-le", errors="surrogatepass")
                    if _is_component(name):
                        self._active_handle()
                        yield name
                if not entry.next_offset:
                    break
                offset = following
        if error != _ERROR_NO_MORE_FILES:
            raise ct.WinError(error)

    def version(self, name):
        handle = self._open_child(name, _FILE_READ_ATTRIBUTES, _SHARE_ALL)
        try:
            return _file_version(handle)
        finally:
            _close(handle)

    @contextmanager
    def open_version(self, name, version):
        # Use one read handle for validation, content and hashing. Denying write
        # sharing also defers reads while an ordinary writer has the file open.
        access = _FILE_READ_DATA | _FILE_READ_ATTRIBUTES
        handle = self._open_child(name, access, _SHARE_READ | _SHARE_DELETE)
        with _binary_stream(handle) as stream:
            if _file_version(handle) != version:
                raise EntryChanged
            yield stream
            if _file_version(handle) != version:
                raise EntryChanged


class FixtureRoot:
    """Keep the original fixture identity alive and confine each scan to it."""

    def __init__(self, path, volume, expected_identity=None):
        self._path = path
        self._volume = volume
        self._lock = Lock()
        with self._open_parent() as parent:
            handle = self._open_root(parent)
            try:
                self._identity = _identity(handle)
                if expected_identity is not None and self._identity != expected_identity:
                    raise ValueError("Dry-run fixture directory was replaced")
                self._release = weakref.finalize(self, _close, handle)
            except BaseException:
                _close(handle)
                raise

    def close(self):
        """Release the identity pin once. Active scans own their own handles."""
        with self._lock:
            self._release()

    def _open_parent(self):
        return _open_directories(self._volume, self._path.parts[1:-1])

    def _open_root(self, parent):
        handle = _open_relative(parent, self._path.name, _DIRECTORY_ACCESS, _SHARE_ALL, directory=True)
        try:
            _require_directory(handle)
        except BaseException:
            _close(handle)
            raise
        return handle

    @contextmanager
    def scan(self):
        with ExitStack() as handles:
            # Keep the identity pin alive until this scan has its own reference.
            with self._lock:
                if not self._release.alive:
                    raise ValueError("Dry-run fixture root is closed")
                parent = handles.enter_context(self._open_parent())
                handle = self._open_root(parent)
                handles.callback(_close, handle)
                if _identity(handle) != self._identity:
                    raise ValueError("Dry-run fixture directory was replaced")
                # A concurrent rename leaves this handle on the original directory.
                scan = DirectoryScan(handle)
            try:
                yield scan
            finally:
                scan._end()


@contextmanager
def _open_directories(volume, parts):
    with ExitStack() as stack:
        handle = _open_absolute(volume, _FILE_TRAVERSE | _FILE_READ_ATTRIBUTES,
                                _FILE_FLAG_BACKUP_SEMANTICS | _OPEN_REPARSE_POINT)
        stack.callback(_close, handle)
        _require_directory(handle)
        fs = ct.create_unicode_buffer(32)
        if not _get_volume_info(handle, None, 0, None, None, None, fs, len(fs)):
            raise ct.WinError(ct.get_last_error())
        if fs.value != "NTFS":
            raise ValueError("Dry-run requires a local fixed NTFS volume for synthetic fixtures")

        for name in parts:
            handle = _open_relative(handle, name, _DIRECTORY_ACCESS, _SHARE_READ | _SHARE_WRITE,
                                    directory=True)
            stack.callback(_close, handle)
            _require_directory(handle)
        yield handle


class _DemoFixture:
    """Borrow the directory and its cleanup stack during fixture setup."""

    def __init__(self, path, handle, cleanup):
        self.path = path
        self._handle = handle
        self._cleanup = cleanup
        self._lock = Lock()

    def _end(self):
        with self._lock:
            self._handle = None

    def _active_handle(self):
        if self._handle is None:
            raise ValueError("Dry-run demo fixture is closed")
        return self._handle

    @property
    def identity(self):
        with self._lock:
            return _identity(self._active_handle())

    def write_new(self, name, content):
        with self._lock:
            directory = self._active_handle()
            owner = _open_relative(directory, name, _FILE_READ_ATTRIBUTES, _SHARE_ALL,
                                   directory=False, create_temporary=True)
            self._cleanup.callback(_close, owner)
            writer = _open_relative(directory, name, _FILE_WRITE_DATA | _FILE_READ_ATTRIBUTES,
                                    _SHARE_ALL, directory=False)
            with _binary_stream(writer, "wb") as stream:
                if _file_version(writer) is None or _identity(writer) != _identity(owner):
                    raise OSError(f"Synthetic fixture was replaced: {name}")
                stream.write(content)
            return _file_version(owner)


@contextmanager
def temporary_fixture(temp_root):
    """Create and clean up only the directory and files we exclusively create."""
    volume = local_fixture_volume(temp_root.anchor)
    with _open_directories(volume, temp_root.parts[1:]) as parent, ExitStack() as cleanup:
        name = f"dlp-usb-dry-run-{uuid.uuid4().hex}"
        handle = _open_relative(parent, name, _DIRECTORY_ACCESS, _SHARE_ALL,
                                directory=True, create_temporary=True)
        cleanup.callback(_close, handle)
        fixture = _DemoFixture(temp_root / name, handle, cleanup)
        try:
            yield fixture
        finally:
            fixture._end()
