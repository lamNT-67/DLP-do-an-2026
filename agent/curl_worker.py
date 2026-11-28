"""Bounded Windows inspection process with explicitly inherited handles."""

import ctypes
import math
import os
import subprocess
import sys
import threading
import time
from contextlib import ExitStack
from ctypes import wintypes
from pathlib import Path


MAX_INSPECTION_REQUEST = 8 * 1024 * 1024
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
CLEANUP_TIMEOUT = 1.0
_HANDLE_LIST = 0x00020002
_JOB_LIST = 0x0002000D
_CREATE_FLAGS = 0x00080000 | 0x00000400 | 0x08000000  # extended startup, Unicode, no console
_KILL_ON_JOB_CLOSE = 0x00002000
_SIZE_T = ctypes.c_size_t
_HANDLE = wintypes.HANDLE
_DWORD = wintypes.DWORD
_PTR = ctypes.c_void_p


class WorkerCleanupUnconfirmed(OSError):
    """Windows did not confirm that all inspection processes were removed."""


class _StartupInfo(ctypes.Structure):
    _fields_ = [
        ("cb", _DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR), ("dwX", _DWORD), ("dwY", _DWORD),
        ("dwXSize", _DWORD), ("dwYSize", _DWORD), ("dwXCountChars", _DWORD),
        ("dwYCountChars", _DWORD), ("dwFillAttribute", _DWORD), ("dwFlags", _DWORD),
        ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
        ("lpReserved2", _PTR), ("hStdInput", _HANDLE), ("hStdOutput", _HANDLE),
        ("hStdError", _HANDLE),
    ]


class _StartupInfoEx(ctypes.Structure):
    _fields_ = [("StartupInfo", _StartupInfo), ("lpAttributeList", _PTR)]


class _ProcessInformation(ctypes.Structure):
    _fields_ = [("hProcess", _HANDLE), ("hThread", _HANDLE),
                ("dwProcessId", _DWORD), ("dwThreadId", _DWORD)]


class _BasicJobLimits(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", _DWORD), ("MinimumWorkingSetSize", _SIZE_T),
        ("MaximumWorkingSetSize", _SIZE_T), ("ActiveProcessLimit", _DWORD),
        ("Affinity", _SIZE_T), ("PriorityClass", _DWORD), ("SchedulingClass", _DWORD),
    ]


class _JobLimits(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _BasicJobLimits), ("IoInfo", ctypes.c_ulonglong * 6),
        ("ProcessMemoryLimit", _SIZE_T), ("JobMemoryLimit", _SIZE_T),
        ("PeakProcessMemoryUsed", _SIZE_T), ("PeakJobMemoryUsed", _SIZE_T),
    ]


class _JobAccounting(ctypes.Structure):
    _fields_ = [
        ("Times", ctypes.c_longlong * 4), ("TotalPageFaultCount", _DWORD),
        ("TotalProcesses", _DWORD), ("ActiveProcesses", _DWORD),
        ("TotalTerminatedProcesses", _DWORD),
    ]


class _JobProcessIds(ctypes.Structure):
    _fields_ = [
        ("NumberOfAssignedProcesses", _DWORD), ("NumberOfProcessIdsInList", _DWORD),
        ("ProcessIdList", _SIZE_T * 64),
    ]


def _kernel():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    functions = {
        "CloseHandle": (wintypes.BOOL, _HANDLE),
        "CreateJobObjectW": (_HANDLE, _PTR, wintypes.LPCWSTR),
        "SetInformationJobObject": (wintypes.BOOL, _HANDLE, ctypes.c_int, _PTR, _DWORD),
        "QueryInformationJobObject": (wintypes.BOOL, _HANDLE, ctypes.c_int, _PTR, _DWORD, _PTR),
        "TerminateJobObject": (wintypes.BOOL, _HANDLE, wintypes.UINT),
        "OpenProcess": (_HANDLE, _DWORD, wintypes.BOOL, _DWORD),
        "GetProcessId": (_DWORD, _HANDLE),
        "IsProcessInJob": (wintypes.BOOL, _HANDLE, _HANDLE, ctypes.POINTER(wintypes.BOOL)),
        "CreatePipe": (wintypes.BOOL, _PTR, _PTR, _PTR, _DWORD),
        "GetCurrentProcess": (_HANDLE,),
        "DuplicateHandle": (wintypes.BOOL, _HANDLE, _HANDLE, _HANDLE, _PTR,
                            _DWORD, wintypes.BOOL, _DWORD),
        "InitializeProcThreadAttributeList": (wintypes.BOOL, _PTR, _DWORD, _DWORD, _PTR),
        "UpdateProcThreadAttribute": (wintypes.BOOL, _PTR, _DWORD, _SIZE_T, _PTR,
                                      _SIZE_T, _PTR, _PTR),
        "DeleteProcThreadAttributeList": (None, _PTR),
        "CreateProcessW": (wintypes.BOOL, wintypes.LPCWSTR, wintypes.LPWSTR, _PTR, _PTR,
                           wintypes.BOOL, _DWORD, _PTR, wintypes.LPCWSTR, _PTR, _PTR),
        "WaitForSingleObject": (_DWORD, _HANDLE, _DWORD),
        "GetExitCodeProcess": (wintypes.BOOL, _HANDLE, _PTR),
        "GetWindowsDirectoryW": (wintypes.UINT, wintypes.LPWSTR, wintypes.UINT),
    }
    for name, (result, *arguments) in functions.items():
        api = getattr(kernel, name)
        api.argtypes = arguments
        api.restype = result
    return kernel


def _check(result):
    if not result:
        raise ctypes.WinError(ctypes.get_last_error())
    return result


def _new_job(kernel, resources):
    job = _check(kernel.CreateJobObjectW(None, None))
    resources.callback(kernel.CloseHandle, job)
    limits = _JobLimits()
    # Deliberately leave both breakaway flags off.
    limits.BasicLimitInformation.LimitFlags = _KILL_ON_JOB_CLOSE
    _check(kernel.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)))
    return job


def _make_pipe(kernel, resources):
    reader, writer = _HANDLE(), _HANDLE()
    _check(kernel.CreatePipe(ctypes.byref(reader), ctypes.byref(writer), None, 0))
    resources.callback(kernel.CloseHandle, reader.value)
    resources.callback(kernel.CloseHandle, writer.value)
    return reader.value, writer.value


def _copy_handle(kernel, handle, resources, inheritable):
    process = kernel.GetCurrentProcess()
    copy = _HANDLE()
    _check(kernel.DuplicateHandle(process, handle, process, ctypes.byref(copy),
                                  0, inheritable, 2))  # DUPLICATE_SAME_ACCESS
    resources.callback(kernel.CloseHandle, copy.value)
    return copy.value


def _create_process(kernel, job, interpreter, script, child_handles):
    stdin, stdout, stderr, token = child_handles
    command = ctypes.create_unicode_buffer(subprocess.list2cmdline([
        str(interpreter), "-E", "-s", "-B", str(script), "--inspect-worker", "--origin-token", str(token),
    ]))
    windows_dir = ctypes.create_unicode_buffer(32768)
    length = kernel.GetWindowsDirectoryW(windows_dir, len(windows_dir))
    if not 0 < length < len(windows_dir):
        raise OSError("Windows directory unavailable")
    environment = ctypes.create_unicode_buffer(f"SystemRoot={windows_dir.value}\0")

    size = _SIZE_T()
    kernel.InitializeProcThreadAttributeList(None, 2, 0, ctypes.byref(size))
    if not size.value:
        raise OSError("Worker startup attributes unavailable")
    attributes = ctypes.create_string_buffer(size.value)
    _check(kernel.InitializeProcThreadAttributeList(attributes, 2, 0, ctypes.byref(size)))
    try:
        handles = (_HANDLE * 4)(stdin, stdout, stderr, token)
        jobs = (_HANDLE * 1)(job)
        _check(kernel.UpdateProcThreadAttribute(attributes, 0, _HANDLE_LIST, handles,
                                                ctypes.sizeof(handles), None, None))
        # Assign at creation so no process can run, or remain suspended outside the job,
        # if the watcher exits between CreateProcess and a separate assignment call.
        _check(kernel.UpdateProcThreadAttribute(attributes, 0, _JOB_LIST, jobs,
                                                ctypes.sizeof(jobs), None, None))
        startup = _StartupInfoEx()
        startup.StartupInfo.cb = ctypes.sizeof(startup)
        startup.StartupInfo.dwFlags = 0x00000100  # STARTF_USESTDHANDLES
        startup.StartupInfo.hStdInput = stdin
        startup.StartupInfo.hStdOutput = stdout
        startup.StartupInfo.hStdError = stderr
        startup.lpAttributeList = ctypes.cast(attributes, _PTR)
        child = _ProcessInformation()
        _check(kernel.CreateProcessW(str(interpreter), command, None, None, True, _CREATE_FLAGS,
                                     environment, str(script.parent), ctypes.byref(startup),
                                     ctypes.byref(child)))
        kernel.CloseHandle(child.hThread)
        return child.hProcess
    finally:
        kernel.DeleteProcThreadAttributeList(attributes)


def _job_accounting(kernel, job):
    accounting = _JobAccounting()
    _check(kernel.QueryInformationJobObject(job, 1, ctypes.byref(accounting),
                                            ctypes.sizeof(accounting), None))
    return accounting


class _JobMembers:
    def __init__(self, kernel, job, resources):
        self.kernel = kernel
        self.job = job
        self.resources = resources
        self.handles = {}

    def add_worker(self, handle):
        # CreateProcess returned the exact handle and assigned the job atomically.
        self.handles[_check(self.kernel.GetProcessId(handle))] = handle

    def discover(self):
        listing = _JobProcessIds()
        # Includes processes in nested jobs. An oversized or partial list
        # cannot establish coverage of this small inspection job.
        _check(self.kernel.QueryInformationJobObject(self.job, 3, ctypes.byref(listing),
                                                     ctypes.sizeof(listing), None))
        count = listing.NumberOfProcessIdsInList
        if count != listing.NumberOfAssignedProcesses or count > len(listing.ProcessIdList):
            raise OSError("Incomplete inspection job member list")
        for pid in listing.ProcessIdList[:count]:
            if pid in self.handles:
                continue
            # Retained handles keep their PID from being recycled. A new PID
            # from a snapshot is only a hint until its opened object is verified.
            handle = self.kernel.OpenProcess(0x101000, False, pid)  # SYNCHRONIZE | QUERY_LIMITED_INFORMATION
            if not handle:
                continue
            try:
                in_job = wintypes.BOOL()
                if (self.kernel.GetProcessId(handle) == pid
                        and self.kernel.IsProcessInJob(handle, self.job, ctypes.byref(in_job))
                        and in_job.value):
                    self.resources.callback(self.kernel.CloseHandle, handle)
                    self.handles[pid] = handle
                    handle = None
            finally:
                if handle:
                    self.kernel.CloseHandle(handle)


def _reap_job(kernel, job, members, deadline):
    try:
        minimum_total = 0
        while True:
            previous_count = len(members.handles)
            try:
                members.discover()
            finally:
                # Even a failed snapshot must attempt to stop the private job.
                _check(kernel.TerminateJobObject(job, 1))
            if minimum_total and len(members.handles) == previous_count:
                raise OSError("Unable to verify every inspection job member")
            for handle in members.handles.values():
                remaining_ms = max(0, int((deadline - time.monotonic()) * 1000))
                if kernel.WaitForSingleObject(handle, remaining_ms) != 0:
                    raise OSError("Inspection job member did not signal exit")
            # No tracked process can start another child after it signals.
            # Reconcile the lifetime count after the waits to catch members
            # that joined late or exited between snapshots. Holds on signaled
            # objects can outlast their execution and affect active accounting.
            total = _job_accounting(kernel, job).TotalProcesses
            if time.monotonic() > deadline:
                raise OSError("Inspection job cleanup exceeded its deadline")
            if total < max(minimum_total, len(members.handles)):
                raise OSError("Inconsistent inspection job lifetime accounting")
            if total == len(members.handles):
                return
            minimum_total = total
    except OSError as exc:
        # The parent's last non-inherited job handle still closes on this path.
        raise WorkerCleanupUnconfirmed("Could not confirm inspection job cleanup") from exc


class _PipeExchange:
    def __init__(self, reader, writer, payload):
        self.reader = reader
        self.writer = writer
        self.payload = payload
        self.output = bytearray()
        self.overflow = threading.Event()
        self.failed = threading.Event()
        self.read_thread = threading.Thread(target=self._read, daemon=True)
        self.write_thread = threading.Thread(target=self._write, daemon=True)
        self.started = []

    def _read(self):
        try:
            while True:
                chunk = os.read(self.reader, min(65536, MAX_OUTPUT_BYTES + 1 - len(self.output)))
                if not chunk:
                    return
                self.output.extend(chunk)
                if len(self.output) > MAX_OUTPUT_BYTES:
                    self.overflow.set()
                    return
        except BrokenPipeError:
            return
        except OSError:
            self.failed.set()
        finally:
            os.close(self.reader)

    def _write(self):
        try:
            pending = memoryview(self.payload)
            while pending:
                written = os.write(self.writer, pending[:65536])
                if not written:
                    self.failed.set()
                    return
                pending = pending[written:]
        except OSError:
            self.failed.set()
        finally:
            # End of input is part of the protocol. Only this thread closes the FD
            # after it starts, so the same descriptor is never closed twice.
            os.close(self.writer)

    def start(self):
        for thread in (self.read_thread, self.write_thread):
            thread.start()
            self.started.append(thread)

    def alive(self):
        return any(thread.is_alive() for thread in self.started)

    def close(self, deadline):
        for thread in self.started:
            thread.join(max(0, deadline - time.monotonic()))
        if self.write_thread not in self.started:
            os.close(self.writer)
        if self.read_thread not in self.started:
            os.close(self.reader)
        if self.alive():
            raise WorkerCleanupUnconfirmed("Inspection pipe I/O did not finish")


def _monitor(kernel, process, exchange, members, deadline, timeout):
    while True:
        if exchange.overflow.is_set():
            raise ValueError("Inspection worker response exceeded its size limit")
        if exchange.failed.is_set():
            raise OSError("Inspection worker pipe failed")
        if time.monotonic() >= deadline:
            raise subprocess.TimeoutExpired("inspection worker", timeout)
        members.discover()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired("inspection worker", timeout)
        status = kernel.WaitForSingleObject(process, max(1, min(20, int(remaining * 1000))))
        if status == 0:
            if exchange.alive():
                time.sleep(min(remaining, 0.01))
                continue
            if exchange.overflow.is_set() or exchange.failed.is_set():
                raise OSError("Inspection worker pipe did not complete successfully")
            exit_code = _DWORD()
            _check(kernel.GetExitCodeProcess(process, ctypes.byref(exit_code)))
            if exit_code.value:
                raise OSError("Inspection worker exited unsuccessfully")
            return bytes(exchange.output)
        if status != 258:  # WAIT_TIMEOUT
            raise ctypes.WinError(ctypes.get_last_error())


def _open_fd(kernel, handle, flags):
    import msvcrt

    with ExitStack() as cleanup:
        copy = _copy_handle(kernel, handle, cleanup, False)
        fd = msvcrt.open_osfhandle(copy, flags | os.O_BINARY | os.O_NOINHERIT)
        cleanup.pop_all()  # The descriptor now owns its handle.
        return fd


def run_inspection_worker(script_path: Path, payload: bytes, origin_token: int, timeout: float) -> bytes:
    """Launch the trusted entry point with a borrowed, verified impersonation token."""
    if sys.platform != "win32":
        raise OSError("The managed inspection worker requires Windows")
    if not 0 < origin_token < _SIZE_T(-1).value:
        raise ValueError("Invalid inspection token handle")
    if not 0 < len(payload) <= MAX_INSPECTION_REQUEST or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Invalid inspection worker inputs")
    if not Path(sys.executable).is_absolute() or not script_path.is_absolute():
        raise ValueError("Inspection worker paths must be absolute")
    import msvcrt

    interpreter = Path(sys.executable).resolve(strict=True)
    script = script_path.resolve(strict=True)
    deadline = time.monotonic() + timeout
    kernel = _kernel()

    with ExitStack() as resources:
        job = _new_job(kernel, resources)
        members = _JobMembers(kernel, job, resources)
        process = None
        exchange = None
        try:
            with ExitStack() as pipe_handles:
                stdin_reader, stdin_writer = _make_pipe(kernel, pipe_handles)
                stdout_reader, stdout_writer = _make_pipe(kernel, pipe_handles)
                stderr_fd = os.open(os.devnull, os.O_WRONLY | os.O_BINARY | os.O_NOINHERIT)
                pipe_handles.callback(os.close, stderr_fd)
                stderr_handle = msvcrt.get_osfhandle(stderr_fd)
                with ExitStack() as owned_fds:
                    reader_fd = _open_fd(kernel, stdout_reader, os.O_RDONLY)
                    owned_fds.callback(os.close, reader_fd)
                    writer_fd = _open_fd(kernel, stdin_writer, os.O_WRONLY)
                    owned_fds.callback(os.close, writer_fd)
                    with ExitStack() as inherited:
                        handles = tuple(_copy_handle(kernel, handle, inherited, True)
                                        for handle in (stdin_reader, stdout_writer, stderr_handle, origin_token))
                        process = _create_process(kernel, job, interpreter, script, handles)
                        resources.callback(kernel.CloseHandle, process)
                        members.add_worker(process)
                    exchange = _PipeExchange(reader_fd, writer_fd, payload)
                    owned_fds.pop_all()  # Exchange owns both descriptors now.
            exchange.start()
            return _monitor(kernel, process, exchange, members, deadline, timeout)
        finally:
            cleanup_deadline = time.monotonic() + CLEANUP_TIMEOUT
            try:
                try:
                    _reap_job(kernel, job, members, cleanup_deadline)
                finally:
                    if exchange is not None:
                        exchange.close(cleanup_deadline)
            except WorkerCleanupUnconfirmed:
                raise
            except Exception as exc:
                raise WorkerCleanupUnconfirmed("Could not confirm inspection worker cleanup") from exc
