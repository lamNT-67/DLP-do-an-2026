"""Observe native curl.exe HTTP(S) file uploads on Windows."""

import argparse
import configparser
import ctypes
import datetime
import ipaddress
import json
import os
import re
import signal
import stat
import subprocess
import sys
import threading
import time
import uuid
from contextlib import contextmanager, suppress
from pathlib import Path, PureWindowsPath
from queue import Empty, Full, Queue
from typing import NamedTuple
from urllib.parse import urlsplit

import psutil
import requests

from content_inspection import MAX_TEXT_READ_BYTES, TEXT_EXTS, inspect_file, to_report_fields
from log_writer import write_curl_delivery_status, write_log_event
from policy_client import DEFAULT_TIMEOUT, PolicyClient
from policy_utils import get_exit_point_status


EXIT_POINT = "CLIENT_CURL"
PROCESS_NAME = "curl.exe"
POLL_INTERVAL = 0.25
POLICY_REFRESH_INTERVAL = 60
INSPECTION_TIMEOUT = 5
TERMINATION_WAIT_MS = 1000
METADATA_ATTEMPTS = 3
RESUME_CLEANUP_ATTEMPTS = 3
RESUME_RETRY_DELAY = 0.05
MAX_FILES = 32

SHORT_FLAGS = {
    "G": "get", "I": "head", "q": "disable", "g": "globoff", "s": "silent",
    "S": "show-error", "f": "fail", "v": "verbose", "k": "insecure", "i": "include",
    "O": "remote-name", "N": "no-buffer", "h": "help", "V": "version",
}
SHORT_VALUES = {
    "T": "upload-file", "F": "form", "d": "data", "X": "request", "H": "header",
    "o": "output", "u": "user", "A": "user-agent", "e": "referer", "m": "max-time",
    "w": "write-out", "D": "dump-header",
}
LONG_FLAGS = set(SHORT_FLAGS.values()) | {
    "no-get", "no-head", "no-progress-meter", "fail-with-body", "http1.1", "http2",
}
LONG_VALUES = set(SHORT_VALUES.values()) | {
    "data-ascii", "data-binary", "data-raw", "form-string", "url", "noproxy",
    "connect-timeout", "limit-rate", "expect100-timeout", "output-dir",
}
DATA_OPTIONS = {"data", "data-ascii", "data-binary", "data-raw"}
FORM_OPTIONS = {"form", "form-string"}
FORM_FILE = re.compile(r'(?:"(?P<quoted>(?:\\["\\]|\\(?!["\\])|[^"\\])*)"|(?P<plain>[^",;]+))')
FORM_ATTRIBUTES = re.compile(r'(?:;[ \t]*(?:type|filename)=[^",;]+)*')
VERDICT_PRIORITY = {"ALLOW": 0, "LOG": 1, "BLOCK": 2}
INCOMPLETE_INSPECTIONS = {"UNREADABLE", "TOO_LARGE", "ENCRYPTED_CONTENT", "NOT_INSPECTABLE"}
LIMITED_EXTRACTION_NOTES = {
    "ARCHIVE_TRUNCATED", "BEST_EFFORT_STRINGS", "MEMBER_TOO_LARGE",
    "NESTED_ARCHIVE_SKIPPED", "PDF_TRUNCATED", "ZIP_BOMB_SUSPECT",
}


class UnsupportedSyntax(ValueError):
    """The message is a fixed diagnostic code safe for event logs."""


class ProcessMetadataUnavailable(RuntimeError):
    """A process metadata read may succeed on a subsequent scan."""


class Upload(NamedTuple):
    path: str
    destination: str


class Termination(NamedTuple):
    attempted: bool
    outcome: str


class Resume(NamedTuple):
    outcome: str
    error: str | None = None


def _options(argv):
    """Yield normalized options from Windows argv, with all operands kept intact."""
    tokens = iter(argv[1:])
    for token in tokens:
        if token == "--":
            for url in tokens:
                yield "url", url
            break
        if token.startswith("--"):
            name, separator, value = token[2:].partition("=")
            if name in LONG_VALUES:
                value = value if separator else next(tokens, None)
                if value is None:
                    raise UnsupportedSyntax("MISSING_OPTION_VALUE")
                yield name, value
            elif name in LONG_FLAGS and not separator:
                yield name, None
            else:
                raise UnsupportedSyntax("UNSUPPORTED_OPTION")
        elif token.startswith("-"):
            if token == "-":
                raise UnsupportedSyntax("UNSUPPORTED_OPTION")
            for index, flag in enumerate(token[1:], start=1):
                if flag in SHORT_VALUES:
                    value = token[index + 1:] or next(tokens, None)
                    if value is None:
                        raise UnsupportedSyntax("MISSING_OPTION_VALUE")
                    yield SHORT_VALUES[flag], value
                    break
                if flag not in SHORT_FLAGS:
                    raise UnsupportedSyntax("UNSUPPORTED_OPTION")
                yield SHORT_FLAGS[flag], None
        else:
            yield "url", token


def _form_file(value):
    field, separator, content = value.partition("=")
    if not separator or not field:
        raise UnsupportedSyntax("UNSUPPORTED_FORM")
    if not content.startswith(("@", "<")):
        if ";" in content or content.startswith("("):
            raise UnsupportedSyntax("UNSUPPORTED_FORM")
        return None
    operand = content[1:].lstrip(" \t")
    match = FORM_FILE.match(operand)
    if not match or not FORM_ATTRIBUTES.fullmatch(operand[match.end():].lstrip(" \t\r\n\v\f")):
        raise UnsupportedSyntax("UNSUPPORTED_FORM")
    quoted = match["quoted"]
    if quoted is not None:
        return re.sub(r'\\(["\\])', r'\1', quoted)
    return match["plain"].rstrip(" \t")


def _check_local_path(path):
    windows_path = PureWindowsPath(path)
    tail = path[len(windows_path.drive):]
    if (
        not path or path in {"-", "."} or path.startswith(("\\\\", "//", "\\/", "/\\"))
        or (windows_path.drive and not windows_path.root)
        or windows_path.is_reserved()
        or any(char in tail for char in '<>:"|?*')
        or any(ord(char) < 32 for char in path)
    ):
        raise UnsupportedSyntax("UNSUPPORTED_SOURCE_PATH")


def _http_destination(url):
    try:
        if "\\" in url or any(char.isspace() or ord(char) < 32 for char in url):
            raise UnsupportedSyntax("UNSUPPORTED_DESTINATION")
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port
        userinfo = parsed.netloc.rpartition("@")[0]
        if any(char in userinfo + parsed.path + parsed.query + parsed.fragment for char in "[]{}"):
            raise UnsupportedSyntax("URL_GLOB")
        if parsed.scheme in {"http", "https"} and host:
            port = port if port is not None else (443 if parsed.scheme == "https" else 80)
            if ":" in host and "%" not in host:
                return f"[{ipaddress.IPv6Address(host)}]:{port}"
            if re.fullmatch(r"[a-z0-9_.-]+", host):
                return f"{host}:{port}"
    except UnsupportedSyntax:
        raise
    except ValueError:
        pass
    raise UnsupportedSyntax("UNSUPPORTED_DESTINATION")


def parse_uploads(argv):
    """Find explicit HTTP(S) file operands, or raise a coverage diagnostic."""
    urls, paths, body_options = [], [], set()
    head = get = False
    for option, value in _options(argv):
        if option in {"help", "version"}:
            return []
        if option == "url":
            urls.append(value)
        elif option == "header" and value.startswith("@"):
            raise UnsupportedSyntax("FILE_BACKED_HEADER")
        elif option in {"head", "no-head"}:
            head = option == "head"
        elif option in {"get", "no-get"}:
            get = option == "get"
        elif option == "upload-file":
            body_options.add("put")
            if any(char in value for char in "{}[]"):
                raise UnsupportedSyntax("UPLOAD_GLOB")
            paths.append(value)
        elif option in DATA_OPTIONS:
            body_options.add("data")
            if option != "data-raw" and value.startswith("@"):
                paths.append(value[1:])
        elif option in FORM_OPTIONS:
            body_options.add("form")
            if option == "form":
                path = _form_file(value)
                if path is not None:
                    paths.append(path)

    if not paths:
        return []
    if head or get or len(body_options) > 1:
        raise UnsupportedSyntax("UNSUPPORTED_REQUEST_MODE")
    if len(paths) > MAX_FILES:
        raise UnsupportedSyntax("TOO_MANY_FILES")
    for path in paths:
        _check_local_path(path)
    if body_options == {"put"} and len(urls) == len(paths):
        return [Upload(path, _http_destination(url)) for path, url in zip(paths, urls)]
    if body_options != {"put"} and len(urls) == 1:
        destination = _http_destination(urls[0])
        return [Upload(path, destination) for path in paths]
    raise UnsupportedSyntax("AMBIGUOUS_DESTINATION")


def _resolve_uploads(proc, uploads):
    cwd = None
    if any(not Path(upload.path).is_absolute() for upload in uploads):
        try:
            cwd = proc.cwd()
        except psutil.NoSuchProcess:
            raise
        except (psutil.Error, OSError):
            raise ProcessMetadataUnavailable("WORKING_DIRECTORY_UNAVAILABLE") from None
        if not cwd or not Path(cwd).is_absolute():
            raise ProcessMetadataUnavailable("WORKING_DIRECTORY_UNAVAILABLE")

    resolved = []
    for upload in uploads:
        path = os.path.normpath(os.path.join(cwd, upload.path) if cwd else upload.path)
        _check_local_path(path)
        resolved.append(Upload(path, upload.destination))
    return list(dict.fromkeys(resolved))


def _diagnostic(reason):
    return {"verdict": None, "reason": reason, "inspected": False}


def _is_local_windows_volume(root):
    from ctypes import wintypes

    get_type = ctypes.WinDLL("kernel32").GetDriveTypeW
    get_type.argtypes = (wintypes.LPCWSTR,)
    get_type.restype = wintypes.UINT
    return get_type(root) in {2, 3, 5, 6}  # Removable, fixed, CD-ROM, or RAM disk.


def _windows_final_path(stream):
    import msvcrt
    from ctypes import wintypes

    get_path = ctypes.WinDLL("kernel32").GetFinalPathNameByHandleW
    get_path.argtypes = (wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD)
    get_path.restype = wintypes.DWORD
    buffer = ctypes.create_unicode_buffer(32768)
    length = get_path(msvcrt.get_osfhandle(stream.fileno()), buffer, len(buffer), 0)
    if not 0 < length < len(buffer) or not buffer.value.startswith("\\\\?\\"):
        raise UnsupportedSyntax("UNVERIFIED_SOURCE_PATH")
    return buffer.value[4:]


@contextmanager
def _open_local_file(path):
    """Provide the shared engine with a single handle for inspection and hashing."""
    source = Path(path)
    if sys.platform == "win32":
        if not _is_local_windows_volume(source.anchor):
            raise UnsupportedSyntax("NON_LOCAL_SOURCE_VOLUME")
        # Inspect each component from the root down before following any link.
        for component in (*reversed(source.parents), source):
            attributes = component.lstat()
            if attributes.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                raise UnsupportedSyntax("UNSUPPORTED_SOURCE_ALIAS")
    else:
        attributes = source.lstat()
    if not stat.S_ISREG(attributes.st_mode):
        raise UnsupportedSyntax("NON_REGULAR_FILE")
    with source.open("rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise UnsupportedSyntax("NON_REGULAR_FILE")
        if sys.platform == "win32" and os.path.normcase(_windows_final_path(stream)) != os.path.normcase(path):
            raise UnsupportedSyntax("UNSUPPORTED_SOURCE_ALIAS")
        yield stream


def _inspect_uploads(uploads, status):
    results = []
    for path, destination in uploads:
        try:
            result = inspect_file(path, status, destination=destination, enforce_file_scope=True,
                                  open_stream=lambda: _open_local_file(path))
            fields = to_report_fields(result)
            del fields["file_path"]
            if result["reason"] in INCOMPLETE_INSPECTIONS:
                fields["inspection_limit"] = result["reason"]
            elif (any(note.split(":", 1)[0] in LIMITED_EXTRACTION_NOTES for note in result["notes"])
                  or (result["inspected"] and result["real_type"] in TEXT_EXTS
                      and result["file_size"] > MAX_TEXT_READ_BYTES)):
                fields["inspection_limit"] = "PARTIAL_CONTENT_INSPECTION"
            results.append({
                **fields,
                "verdict": result["verdict"], "reason": result["reason"],
                "inspected": result["inspected"], "policy_id": result.get("policy_id"),
                "policy_action": result["policy_action"],
            })
            if result["verdict"] == "BLOCK":
                break
        except UnsupportedSyntax as exc:
            results.append(_diagnostic(str(exc)))
        except Exception:
            results.append(_diagnostic("INSPECTION_ERROR"))
    return results


def _inspect_in_worker(uploads, status):
    # Use a worker timeout for stalled file I/O or policy regex evaluation.
    finished = subprocess.run(
        [sys.executable, "-B", str(Path(__file__).resolve()), "--inspect-worker"],
        input=json.dumps([uploads, status]), encoding="utf-8", stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, check=True, timeout=INSPECTION_TIMEOUT,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    return json.loads(finished.stdout)


def _terminate_windows(proc):
    # psutil.kill() on Windows can return success after TerminateProcess reports
    # ERROR_ACCESS_DENIED on an already exited process. Check the native result
    # and wait on the same handle so a recycled PID cannot confirm termination.
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32")
    kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.TerminateProcess.argtypes = (wintypes.HANDLE, wintypes.UINT)
    kernel.TerminateProcess.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.CloseHandle.restype = wintypes.BOOL

    wait_signaled, wait_timeout = 0, 258
    synchronize, process_terminate = 0x00100000, 0x0001
    if not proc.is_running():
        return Termination(False, "EXITED_BEFORE_TERMINATION")
    handle = kernel.OpenProcess(synchronize | process_terminate, False, proc.pid)
    if not handle:
        if not proc.is_running():
            return Termination(False, "EXITED_BEFORE_TERMINATION")
        return Termination(False, "TERMINATION_HANDLE_UNAVAILABLE")
    try:
        state = kernel.WaitForSingleObject(handle, 0)
        if state == wait_signaled or not proc.is_running():
            return Termination(False, "EXITED_BEFORE_TERMINATION")
        if state != wait_timeout:
            return Termination(False, "TERMINATION_WAIT_FAILED")
        if not kernel.TerminateProcess(handle, signal.SIGTERM):
            if kernel.WaitForSingleObject(handle, 0) == wait_signaled:
                return Termination(True, "EXITED_DURING_TERMINATION_ATTEMPT")
            return Termination(True, "TERMINATION_FAILED")
        if kernel.WaitForSingleObject(handle, TERMINATION_WAIT_MS) == wait_signaled:
            return Termination(True, "CONFIRMED")
        return Termination(True, "TERMINATION_UNCONFIRMED")
    finally:
        kernel.CloseHandle(handle)


def _resume(proc):
    try:
        if not proc.is_running():
            return Resume("PROCESS_EXITED")
        proc.resume()
    except psutil.NoSuchProcess:
        return Resume("PROCESS_EXITED")
    except (psutil.AccessDenied, PermissionError):
        return Resume("RESUME_FAILED", "ACCESS_DENIED")
    except (psutil.Error, OSError):
        return Resume("RESUME_FAILED", "OS_ERROR")
    return Resume("RESUMED")


class CurlMonitor:
    def __init__(self, record, inspect_uploads=_inspect_in_worker, terminate=_terminate_windows):
        self.record = record
        self.inspect_uploads = inspect_uploads
        self.terminate = terminate
        self.seen = set()
        self.metadata_attempts = {}
        self.pending_resume = {}

    def retry_resumes(self):
        failures = {}
        for key, proc in list(self.pending_resume.items()):
            resume = _resume(proc)
            if resume.error is None:
                del self.pending_resume[key]
                self.record(key, None, _diagnostic("RESUME_RETRY"), {"resume": resume.outcome})
            else:
                failures[key] = resume.error
        return failures

    def cleanup(self):
        for attempt in range(RESUME_CLEANUP_ATTEMPTS):
            failures = self.retry_resumes()
            if not failures:
                return
            if attempt + 1 < RESUME_CLEANUP_ATTEMPTS:
                time.sleep(RESUME_RETRY_DELAY)
        for key, error in failures.items():
            self.record(key, None, _diagnostic("RESUME_CLEANUP_INCOMPLETE"),
                        {"resume": "RESUME_FAILED", "resume_error": error})

    def poll(self, status, processes=None, *, stop=None):
        self.retry_resumes()
        if not status["is_governed"]:
            self.seen.clear()
            self.metadata_attempts.clear()
            return
        if processes is None:
            # Since psutil 6, process_iter caches Windows names and creation times
            # without verifying PID reuse.
            clear_cache = getattr(psutil.process_iter, "cache_clear", None)
            if clear_cache is not None:
                clear_cache()
            processes = psutil.process_iter(["name"])
        current = set()
        for proc in processes:
            if stop is not None and stop.is_set():
                break
            if (proc.info.get("name") or "").lower() != PROCESS_NAME:
                continue
            key = (proc.pid, None)
            try:
                key = (proc.pid, proc.create_time())
                current.add(key)
                if key in self.seen or key in self.pending_resume or not proc.is_running():
                    continue
                error = self._handle(proc, key, status, stop)
            except psutil.NoSuchProcess:
                continue
            except (psutil.Error, OSError):
                # Until creation time is readable, account for the failure by
                # PID only. Fresh scans can still discover a new identity.
                if key[1] is None:
                    current.add(key)
                    if key in self.seen:
                        continue
                    error = "PROCESS_IDENTITY_UNAVAILABLE"
                else:
                    error = "PROCESS_ACCESS_UNAVAILABLE"
            if error:
                attempts = self.metadata_attempts.get(key, 0) + 1
                if attempts < METADATA_ATTEMPTS:
                    self.metadata_attempts[key] = attempts
                    continue
                self.record(key, None, _diagnostic(error), None)
            self.seen.add(key)
            self.metadata_attempts.pop(key, None)
        self.seen.intersection_update(current)
        self.metadata_attempts = {key: attempts for key, attempts in self.metadata_attempts.items()
                                  if key in current}

    def _handle(self, proc, key, status, stop):
        try:
            argv = proc.cmdline()
            if not argv:
                raise ProcessMetadataUnavailable("COMMAND_LINE_UNAVAILABLE")
            uploads = _resolve_uploads(proc, parse_uploads(argv))
        except psutil.NoSuchProcess:
            return
        except ProcessMetadataUnavailable as exc:
            return str(exc)
        except (psutil.Error, OSError):
            return "COMMAND_LINE_UNAVAILABLE"
        except UnsupportedSyntax as exc:
            self.record(key, None, _diagnostic(str(exc)), None)
            return
        if not uploads or (stop is not None and stop.is_set()):
            return

        suspension, resume = "NOT_ATTEMPTED", Resume("NOT_NEEDED")
        termination = Termination(False, "NOT_REQUESTED")
        winner = None
        limitations = []
        try:
            if status["effective_action"] == "BLOCK":
                try:
                    proc.suspend()
                    self.pending_resume[key] = proc
                    suspension = "SUSPENDED"
                except psutil.NoSuchProcess:
                    suspension = "PROCESS_EXITED"
                except (psutil.Error, OSError):
                    suspension = "SUSPEND_FAILED"

            if stop is not None and stop.is_set():
                return
            incomplete_reason = "INSPECTION_INCOMPLETE"
            try:
                results = self.inspect_uploads(uploads, status)
            except subprocess.TimeoutExpired:
                incomplete_reason = "INSPECTION_TIMEOUT"
                results = []
            except Exception:
                incomplete_reason = "INSPECTION_ERROR"
                results = []

            for upload, result in zip(uploads, results):
                verdict = result["verdict"]
                if verdict is None:
                    limitations.append((upload, result))
                    continue
                if limit := result.get("inspection_limit"):
                    limitations.append((upload, {**result, "coverage": True, "reason": limit}))
                    if verdict == "ALLOW":
                        continue
                if winner is None or VERDICT_PRIORITY[verdict] > VERDICT_PRIORITY[winner[1]["verdict"]]:
                    winner = (upload, result)
            if winner and winner[1]["verdict"] == "BLOCK":
                incomplete_reason = "NOT_SCANNED_AFTER_BLOCK"
                if suspension == "PROCESS_EXITED":
                    termination = Termination(False, "EXITED_BEFORE_TERMINATION")
                else:
                    try:
                        termination = self.terminate(proc)
                    except psutil.NoSuchProcess:
                        termination = Termination(False, "EXITED_BEFORE_TERMINATION")
                    except (psutil.Error, OSError):
                        termination = Termination(False, "TERMINATION_FAILED")
            for upload in uploads[len(results):]:
                limitations.append((upload, _diagnostic(incomplete_reason)))
        finally:
            if key in self.pending_resume:
                if termination.outcome in {"CONFIRMED", "EXITED_BEFORE_TERMINATION",
                                           "EXITED_DURING_TERMINATION_ATTEMPT"}:
                    resume = Resume("PROCESS_EXITED")
                else:
                    resume = _resume(proc)
                if resume.error is None:
                    del self.pending_resume[key]

        enforcement = {
            "suspension": suspension, "termination_attempted": termination.attempted,
            "termination": termination.outcome, "resume": resume.outcome,
        }
        if resume.error is not None:
            enforcement["resume_error"] = resume.error
        if winner:
            self.record(key, *winner, enforcement)
        for upload, result in limitations:
            self.record(key, upload, result, enforcement)


def _report_text(value, byte_limit):
    if value is not None:
        try:
            if len(value.encode("utf-8")) <= byte_limit:
                return value
        except UnicodeError:
            pass
    return None


def _report_rule_ids(rule_ids):
    selected = []
    used = 0
    for rule_id in rule_ids:
        if type(rule_id) is not int or not 0 < rule_id <= 2**63 - 1:
            continue
        used += len(str(rule_id)) + bool(selected)
        if used > 255:
            break
        selected.append(rule_id)
    return selected


class CurlJournal:
    """Attempt local journaling before sending each report once in the background."""

    def __init__(self, hostname, client):
        self.hostname = hostname
        self.client = client
        self.reports = Queue(maxsize=128)
        self.closing = threading.Event()
        self.abandon_reports = threading.Event()
        self.worker = None
        if client is not None:
            self.worker = threading.Thread(target=self._deliver, daemon=True)
            self.worker.start()

    def record(self, key, upload, result, enforcement):
        verdict = result["verdict"]
        coverage = verdict is None or result.get("coverage", False)
        action = "LOGGED"
        if not coverage and verdict == "BLOCK" and enforcement["termination"] == "CONFIRMED":
            action = "BLOCKED_KILL"
        elif not coverage and verdict == "ALLOW" and enforcement["resume"] != "RESUME_FAILED":
            action = "ALLOWED"
        event_type = ("coverage" if coverage else
                      {"ALLOWED": "allowed", "BLOCKED_KILL": "violation", "LOGGED": "logged"}[action])
        should_report = not coverage and self.client is not None and verdict in {"BLOCK", "LOG"}
        event_id = uuid.uuid4().hex
        filename = os.path.basename(upload.path) if upload else None
        destination = upload.destination if upload else None
        try:
            write_log_event(
                self.hostname, "curl", EXIT_POINT, event_type, result.get("policy_action"),
                {"process_name": PROCESS_NAME, "process_pid": key[0], "process_create_time": key[1]},
                {"file_path": filename, "destination_value": destination}, result, action, False,
                event_id=event_id, policy_id=result.get("policy_id"),
                report_configured=should_report, durable=True, enforcement=enforcement,
            )
        except (OSError, UnicodeError):
            print(f"[curl_agent] Could not write local event {event_id}.", file=sys.stderr, flush=True)
            if should_report:
                self._record_delivery(event_id, "LOCAL_EVENT_FAILED")
        if should_report:
            payload = {
                "hostname": self.hostname, "exit_point_type": EXIT_POINT,
                "policy_id": result.get("policy_id"), "action_taken": action,
                "occurred_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                "file_path": _report_text(filename, 500),
                "file_hash_sha256": result["file_hash_sha256"],
                "matched_rule_ids": _report_rule_ids(result["matched_rule_ids"]),
                "confidence_score": result["confidence_score"],
                "destination_value": _report_text(destination, 255), "process_name": PROCESS_NAME,
            }
            if self.closing.is_set():
                self._record_delivery(event_id, "NOT_QUEUED")
                return
            try:
                self.reports.put_nowait((event_id, payload))
            except Full:
                self._record_delivery(event_id, "NOT_QUEUED")

    def close(self, timeout=2):
        """Stop taking reports and allow a bounded drain on graceful shutdown."""
        self.closing.set()
        if self.worker is None:
            return True
        self.worker.join(timeout)
        if self.worker.is_alive():
            self.abandon_reports.set()
            print("[curl_agent] Report drain timed out. Some reports may be queued or in flight.",
                  file=sys.stderr, flush=True)
            return False
        return True

    def _deliver(self):
        while not self.abandon_reports.is_set():
            try:
                event_id, payload = self.reports.get(timeout=0.1)
            except Empty:
                if self.closing.is_set():
                    return
                continue
            try:
                if self.abandon_reports.is_set():
                    return
                try:
                    log_id = self.client.send_report(payload, require_ack=True)
                except Exception:
                    log_id = None
                if type(log_id) is int and log_id > 0:
                    self._record_delivery(event_id, "ACKNOWLEDGED", log_id)
                else:
                    self._record_delivery(event_id, "UNACKNOWLEDGED")
            finally:
                self.reports.task_done()

    @staticmethod
    def _record_delivery(event_id, status, log_id=None):
        try:
            write_curl_delivery_status(event_id, status, server_log_id=log_id)
        except (OSError, UnicodeError):
            print(f"[curl_agent] Could not write report delivery status for {event_id}.",
                  file=sys.stderr, flush=True)


def _is_api_base_url(value):
    if any(char in value for char in "\\?#") or any(char.isspace() or ord(char) < 32 for char in value):
        return False
    try:
        parsed = urlsplit(value)
        port = parsed.port
        return (parsed.scheme in ("http", "https") and bool(parsed.hostname)
                and parsed.username is None and port != 0)
    except ValueError:
        return False


def _valid_hostname(value):
    try:
        return bool(value.strip(" \t\n\r\v\0")) and len(value.encode("utf-8")) <= 100
    except UnicodeError:
        return False


class CurlPolicyClient(PolicyClient):
    """Keep raw request errors out of this watcher's policy refresh logs."""

    def __init__(self, server_url, hostname, api_token):
        if not _is_api_base_url(server_url):
            raise ValueError("Use an HTTP(S) API base URL without credentials, a query, or a fragment.")
        super().__init__(server_url, hostname, api_token)

    def get_policy(self):
        response = requests.get(f"{self.server_url}/agent_policy.php",
                                params={"hostname": self.hostname}, headers=self._headers(),
                                timeout=DEFAULT_TIMEOUT)
        if response.status_code != 200:
            raise ValueError("Policy endpoint did not return HTTP 200.")
        return response.json()


def _policy_list(record, field):
    values = record.get(field)
    if not isinstance(values, list):
        raise ValueError("Expected a policy list field.")
    return values


def _policy_strings(record, field):
    values = _policy_list(record, field)
    if not all(isinstance(value, str) and value.strip() for value in values):
        raise ValueError("Expected nonempty policy strings.")
    return list(values)


def _policy_id(value, *, from_pdo=False):
    # The endpoint casts policy_id explicitly. Nested IDs are fetched from PDO.
    if from_pdo and isinstance(value, str) and re.fullmatch(r"[1-9][0-9]{0,9}", value):
        value = int(value)
    if type(value) is not int or not 0 < value <= 2**31 - 1:
        raise ValueError("Expected a positive SQL INT policy identifier.")
    return value


def _policy_file_type(record):
    if (not isinstance(record, dict)
            or not isinstance(record.get("extension"), str) or not record["extension"].strip()
            or record.get("category") not in ("DOCUMENT", "ARCHIVE", "IMAGE", "EXECUTABLE", "OTHER")
            or type(record.get("always_block_regardless_content")) is not bool):
        raise ValueError("Invalid policy file type.")
    return {
        "id": _policy_id(record.get("id"), from_pdo=True),
        "extension": record["extension"], "category": record["category"],
        "always_block_regardless_content": record["always_block_regardless_content"],
    }


def _policy_rule(record):
    if (not isinstance(record, dict) or not isinstance(record.get("rule_name"), str)
            or not isinstance(record.get("pattern"), str)
            or record.get("rule_type") not in ("REGEX", "DICTIONARY")
            or record.get("category") not in ("PII", "FINANCE", "INTERNAL_DOC")
            or record.get("severity") not in ("LOW", "MEDIUM", "HIGH", "CRITICAL")):
        raise ValueError("Invalid policy content rule.")
    return {
        "id": _policy_id(record.get("id"), from_pdo=True),
        **{field: record[field] for field in ("rule_name", "pattern", "rule_type", "category", "severity")},
    }


def _policy_snapshot(data):
    if not isinstance(data, dict):
        raise ValueError("Invalid policy response.")
    policies = []
    seen_ids = set()
    for record in _policy_list(data, "applicable_policies"):
        if (not isinstance(record, dict) or not isinstance(record.get("name"), str)
                or record.get("action") not in ("BLOCK", "REPORT_ONLY")):
            raise ValueError("Invalid policy.")
        policy_id = _policy_id(record.get("policy_id"))
        if policy_id in seen_ids:
            raise ValueError("Duplicate policy identifier.")
        seen_ids.add(policy_id)
        exit_points = _policy_strings(record, "exit_points")
        if not exit_points:
            raise ValueError("Expected at least one exit point per policy.")
        policies.append({
            "policy_id": policy_id, "name": record["name"], "action": record["action"],
            "exit_points": exit_points,
            "allowed_files": _policy_strings(record, "allowed_files"),
            "allowed_locations": _policy_strings(record, "allowed_locations"),
            "file_types": [_policy_file_type(item) for item in _policy_list(record, "file_types")],
            "content_rules": [_policy_rule(item) for item in _policy_list(record, "content_rules")],
        })
    return get_exit_point_status(policies, EXIT_POINT)


class CurlPolicy:
    def __init__(self, client):
        self.client = client
        self.status = get_exit_point_status([], EXIT_POINT)
        self._has_valid_policy = False

    def refresh(self):
        try:
            snapshot = _policy_snapshot(self.client.get_policy())
        except Exception:
            fallback = ("Keeping the last valid policy snapshot." if self._has_valid_policy
                        else "Curl enforcement is inactive until the first valid policy response.")
            with suppress(OSError, ValueError):
                print(f"[curl_agent] Policy refresh failed. {fallback}", file=sys.stderr, flush=True)
            return
        # Publish only the complete, validated replacement. The poller reads one snapshot per pass.
        self.status = snapshot
        self._has_valid_policy = True

    def run(self, stop):
        while not stop.is_set():
            self.refresh()
            stop.wait(POLICY_REFRESH_INTERVAL)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Monitor curl.exe HTTP(S) file uploads.")
    parser.add_argument("--config", type=Path, default=Path(__file__).with_name("config.ini"))
    parser.add_argument("--inspect-worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.inspect_worker:
        uploads, status = json.load(sys.stdin.buffer)
        print(json.dumps(_inspect_uploads(uploads, status)))
        return 0
    if sys.platform != "win32":
        parser.error("Curl Agent requires Windows.")
    config = configparser.ConfigParser(interpolation=None)
    try:
        config.read(args.config, encoding="utf-8-sig")
    except (configparser.Error, OSError, UnicodeError):
        parser.error("Could not read the DLP config.ini.")
    agent = config["agent"] if config.has_section("agent") else {}
    hostname = agent.get("hostname", "")
    token = agent.get("api_token", "").strip()
    if not token or not hostname or not agent.get("server_url"):
        parser.error("Use a DLP config.ini with the hostname, server URL, and enrolled device token.")
    if not _valid_hostname(hostname):
        parser.error("Use a nonempty device hostname of at most 100 UTF-8 bytes.")

    try:
        client = CurlPolicyClient(agent["server_url"], hostname, token)
    except ValueError as exc:
        parser.error(str(exc))
    policy = CurlPolicy(client)
    journal = CurlJournal(hostname, client)
    monitor = CurlMonitor(journal.record)
    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    threading.Thread(target=policy.run, args=(stop,), daemon=True).start()
    print("[curl_agent] Watching for curl.exe. Press Ctrl+C to stop.", flush=True)
    try:
        while not stop.is_set():
            monitor.poll(policy.status, stop=stop)
            stop.wait(POLL_INTERVAL)
    finally:
        try:
            monitor.cleanup()
            if monitor.pending_resume:
                print("[curl_agent] Windows refused to resume one or more curl processes.",
                      file=sys.stderr, flush=True)
        finally:
            journal.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
