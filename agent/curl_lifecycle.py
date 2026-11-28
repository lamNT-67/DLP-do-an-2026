"""Admission and operational cleanup receipts for limited, interactive Curl watchers."""

import ctypes
from ctypes import wintypes
from contextlib import ExitStack, contextmanager
import hashlib
import json
from pathlib import Path
import re
import struct
import threading
import uuid


CONTROL_KEY = r"SOFTWARE\DLP\ManagedCurl"
_LOCAL_KEY = CONTROL_KEY + r"\Logons"
_ID = re.compile(r"[a-f0-9]{32}")
_OUTCOME_FIELDS = {"worker_cleanup_confirmed", "pending_resumes", "report_drained", "runtime_failed"}


def _scope_name(scope):
    identity = scope.user_sid + struct.pack("<QI", scope.authentication_id, scope.session_id)
    return hashlib.sha256(identity).hexdigest()


def _control_value(reg, key, name):
    value, kind = reg.QueryValueEx(key, name)
    if kind != reg.REG_SZ or (value != "" and not _ID.fullmatch(value)):
        raise ValueError("Invalid managed Curl control state.")
    return value


def _managed_installed():
    import winreg
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, CONTROL_KEY, 0,
                             winreg.KEY_QUERY_VALUE | winreg.KEY_WOW64_64KEY)
    except FileNotFoundError:
        return False
    with key:
        # A retained inventory permits standalone only after confirmed teardown.
        return bool(_control_value(winreg, key, "Current") or _control_value(winreg, key, "Maintenance"))


@contextmanager
def standalone_admission(scope=None):
    """Keep the unscoped lab watcher off a managed endpoint, including during maintenance."""
    if _managed_installed():
        yield False
        return
    if scope is None:
        from curl_windows import OriginUnavailable, watcher_scope
        try:
            scope = watcher_scope()
        except OriginUnavailable:
            # On an unmanaged machine, preserve standalone V1's supported lab invocation.
            yield not _managed_installed()
            return
    with _singleton(_scope_name(scope)) as first:
        yield first and not _managed_installed()


@contextmanager
def _singleton(name):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateMutexW
    create.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    create.restype = wintypes.HANDLE
    close = kernel.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    ctypes.set_last_error(0)
    handle = create(None, False, "Local\\DLP.ManagedCurl." + name)
    error = ctypes.get_last_error()
    if not handle:
        raise ctypes.WinError(error)
    try:
        # Holding the first non-inheritable object handle defines the watcher lifetime.
        yield error != 183  # ERROR_ALREADY_EXISTS
    finally:
        close(handle)


class _Registry:
    def __init__(self, stack):
        import winreg
        self.reg = winreg
        self.stack = stack
        self.view = winreg.KEY_WOW64_64KEY
        self.control = stack.enter_context(winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, CONTROL_KEY, 0, self.view | winreg.KEY_QUERY_VALUE))

    def maintenance(self):
        return _control_value(self.reg, self.control, "Maintenance")

    def current_generation(self):
        generation = _control_value(self.reg, self.control, "Current")
        return bool(generation) and generation == Path(__file__).resolve().parent.name

    def register(self, name, record):
        reg = self.reg
        self.logon = self.stack.enter_context(reg.CreateKeyEx(
            reg.HKEY_CURRENT_USER, _LOCAL_KEY, 0, self.view | reg.KEY_QUERY_VALUE | reg.KEY_SET_VALUE))
        try:
            previous, kind = reg.QueryValueEx(self.logon, name)
        except FileNotFoundError:
            pass
        else:
            # A new boot can also reuse the logon identity. In either case,
            # reconcile only this exact previous instance under the mutex.
            if kind != reg.REG_SZ or not _ID.fullmatch(previous) or not self._previous_resolved(previous):
                raise RuntimeError("Previous Curl cleanup for this logon is unconfirmed.")
        # Open (never create) the installer-owned inventory with the narrow creation right.
        with reg.OpenKey(self.control, "Instances", 0, self.view | reg.KEY_CREATE_SUB_KEY) as parent:
            self.receipt = self.stack.enter_context(reg.CreateKeyEx(
                parent, record["instance"], 0, self.view | reg.KEY_SET_VALUE | reg.KEY_QUERY_VALUE))
        try:
            reg.QueryValueEx(self.receipt, "Record")
        except FileNotFoundError:
            pass
        else:
            raise RuntimeError("Managed Curl instance already registered.")
        self.write(record)
        reg.SetValueEx(self.logon, name, 0, reg.REG_SZ, record["instance"])
        reg.FlushKey(self.logon)

    def _previous_resolved(self, previous):
        reg = self.reg
        with reg.OpenKey(self.control, "Instances\\" + previous, 0, self.view | reg.KEY_QUERY_VALUE) as key:
            data, kind = reg.QueryValueEx(key, "Record")
        if kind != reg.REG_SZ or not isinstance(data, str) or len(data) > 2048:
            return False
        record = json.loads(data)
        if (not isinstance(record, dict) or type(record.get("version")) is not int or record["version"] != 1
                or record.get("instance") != previous or not isinstance(record.get("local_stop"), str)
                or not _ID.fullmatch(record["local_stop"]) or record["local_stop"] == previous):
            return False
        if record.get("state") == "running":
            return self._previous_abandoned(previous, data)
        return (record.get("state") == "complete" and isinstance(record.get("operation"), str)
                and _ID.fullmatch(record["operation"]) and type(record.get("pending_resumes")) is int
                and record["pending_resumes"] == 0 and record.get("worker_cleanup_confirmed") is True
                and type(record.get("runtime_failed")) is bool and type(record.get("report_drained")) is bool)

    def _previous_abandoned(self, previous, original):
        # The installer owns this separate ledger. The watcher can query
        # only the entry named by its existing opaque instance ID.
        reg = self.reg
        try:
            with reg.OpenKey(self.control, "RestartEvidence\\" + previous, 0,
                             self.view | reg.KEY_QUERY_VALUE) as key:
                evidence, kind = reg.QueryValueEx(key, "Disposition")
        except FileNotFoundError:
            return False
        if kind != reg.REG_SZ or not isinstance(evidence, str) or len(evidence) > 8192:
            return False
        disposition = json.loads(evidence)
        return (isinstance(disposition, dict) and disposition.get("reason") == "abandoned_after_full_restart"
                and disposition.get("record") == original
                and all(isinstance(disposition.get(field), str) and _ID.fullmatch(disposition[field])
                        for field in ("operation", "witness")))

    def write(self, record):
        data = json.dumps(record, separators=(",", ":"), allow_nan=False)
        self.reg.SetValueEx(self.receipt, "Record", 0, self.reg.REG_SZ, data)
        self.reg.FlushKey(self.receipt)

    def clear_logon(self, name, instance):
        value, kind = self.reg.QueryValueEx(self.logon, name)
        if kind != self.reg.REG_SZ or value != instance:
            raise RuntimeError("Managed Curl logon ownership changed.")
        self.reg.DeleteValue(self.logon, name)
        self.reg.FlushKey(self.logon)


class ManagedInstance:
    """Register before the first poll. An abnormal exit leaves a persistent running record."""

    def __init__(self, scope):
        self.name = _scope_name(scope)
        self.admitted = False
        self.stop = threading.Event()
        self._stack = ExitStack()
        self._thread = None
        self._maintenance = ""
        self._control_failed = False
        self._record = None

    def __enter__(self):
        try:
            if not self._stack.enter_context(_singleton(self.name)):
                return self
            self._registry = _Registry(self._stack)
            if self._registry.maintenance() or not self._registry.current_generation():
                return self

            self._record = dict(version=1, instance=uuid.uuid4().hex, local_stop=uuid.uuid4().hex,
                                state="running", operation="", **dict.fromkeys(_OUTCOME_FIELDS))
            self._registry.register(self.name, self._record)
            # Close the startup/maintenance race after durable registration, before inspection.
            self._maintenance = self._registry.maintenance()
            if self._maintenance or not self._registry.current_generation():
                self.stop.set()
                self.finish(dict(worker_cleanup_confirmed=True, pending_resumes=0,
                                 report_drained=True, runtime_failed=False))
                return self
            self._thread = threading.Thread(target=self._listen, name="curl-maintenance", daemon=True)
            self._thread.start()
            self.admitted = True
            return self
        except BaseException:
            self._stack.close()
            raise

    def _listen(self):
        while not self.stop.wait(0.25):
            try:
                self._maintenance = self._registry.maintenance()
            except (OSError, ValueError):
                self._control_failed = True
            if self._control_failed or self._maintenance:
                self.stop.set()

    def _join_listener(self):
        self.stop.set()
        if self._thread is not None:
            self._thread.join()

    def finish(self, outcome):
        self._join_listener()
        if self._record is None or self._record["state"] != "running":
            raise RuntimeError("Managed Curl has no open cleanup record.")
        if (not isinstance(outcome, dict) or set(outcome) != _OUTCOME_FIELDS or
                type(outcome["pending_resumes"]) is not int or outcome["pending_resumes"] < 0 or
                any(type(outcome[k]) is not bool for k in _OUTCOME_FIELDS - {"pending_resumes"})):
            raise ValueError("Invalid managed Curl cleanup outcome.")
        operation = self._registry.maintenance()
        if self._control_failed or (self._maintenance and operation != self._maintenance):
            raise RuntimeError("Managed Curl lost its maintenance operation.")
        state = "complete" if outcome["worker_cleanup_confirmed"] and not outcome["pending_resumes"] else "incomplete"
        final = dict(self._record, **outcome, operation=operation or self._record["local_stop"], state=state)
        self._registry.write(final)
        if not operation:
            # A normal logoff can coincide with the installer publishing its stop
            # operation. Bind the finished work to that challenge before releasing the singleton.
            challenge = self._registry.maintenance()
            if challenge:
                final = dict(final, operation=challenge)
                self._registry.write(final)
        self._record = final
        if state == "complete":
            self._registry.clear_logon(self.name, final["instance"])
        return state

    def __exit__(self, *exc_info):
        try:
            self._join_listener()
        finally:
            self._stack.close()
