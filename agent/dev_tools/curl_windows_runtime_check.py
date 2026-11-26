"""Check Windows Curl runtime primitives with synthetic loopback traffic only."""

import argparse
import ctypes
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager, redirect_stdout
from ctypes import wintypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import psutil

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import curl_agent
from curl_receiver_test import MARKER, Receiver, _policy
from curl_windows import OriginUnavailable, impersonate_origin, open_origin, watcher_scope


SCRIPT = Path(__file__).resolve()
SYNTHETIC_ENV = "DLP_RUNTIME_SYNTHETIC_SECRET"


def _emit(**data):
    print(json.dumps(data), flush=True)


def _require(condition, message):
    if not condition:
        raise RuntimeError(message)


def _scope_fields(scope):
    return {"user_sid_sha256": hashlib.sha256(scope.user_sid).hexdigest(),
            "authentication_id": scope.authentication_id, "session_id": scope.session_id,
            "integrity_level": scope.integrity_level}


class HoldHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.server.arrived.set()
        self.server.release.wait(120)
        self.send_response(204)
        self.end_headers()


@contextmanager
def _serve(server):
    with server:
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join()


@contextmanager
def _holding_origin(curl):
    with _serve(ThreadingHTTPServer(("127.0.0.1", 0), HoldHandler)) as server:
        server.arrived = threading.Event()
        server.release = threading.Event()
        url = f"http://127.0.0.1:{server.server_port}/synthetic-origin"
        with subprocess.Popen([curl, "-q", "--noproxy", "*", "--max-time", "125", "-sS", "-o", "NUL", url],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL) as child:
            try:
                _require(server.arrived.wait(5), "Synthetic curl did not connect to the loopback receiver.")
                yield child
            finally:
                server.release.set()
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=5)


def _transfer(curl, receiver, root, scope, name, action, expected):
    records = []
    monitor = curl_agent.CurlMonitor(lambda *event: records.append(event), windows_scope=scope)
    status = curl_agent._policy_snapshot({"applicable_policies": [_policy(action)]})
    source = root / "curl-runtime-source.txt"
    payload = b"synthetic public data" if expected == "ALLOW" else MARKER
    source.write_bytes(payload)
    url = f"http://127.0.0.1:{receiver.server_port}/{name}"
    command = [curl, "-q", "--noproxy", "*", "--max-time", "10", "--http1.1", "-sS", "-o", "NUL",
               "-T", source.name, "-H", "Expect: 100-continue", "--expect100-timeout", "4", url]
    with subprocess.Popen(command, cwd=root, stdin=subprocess.DEVNULL,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as child:
        try:
            deadline = time.monotonic() + 12
            while child.poll() is None and time.monotonic() < deadline:
                candidates = (proc for proc in psutil.process_iter(["name"]) if proc.pid == child.pid)
                monitor.poll(status, candidates)
                time.sleep(curl_agent.POLL_INTERVAL)
            _require(child.poll() is not None, f"The synthetic {name} curl process did not exit.")
        finally:
            try:
                monitor.cleanup()
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=5)
    decisions = [{"verdict": record[2]["verdict"], "reason": record[2]["reason"],
                  "enforcement": record[3]} for record in records]
    requests = tuple(receiver.requests.get(f"/{name}", ()))
    for request in requests:
        _require(request["body_finished"].wait(10), f"Receiver did not finish measuring {name}.")
    received_bytes = sum(request["bytes"] for request in requests)
    complete_requests = sum(request["bytes"] == request["expected"] for request in requests)
    _emit(case=name, decisions=decisions, curl_exit=child.returncode,
          requests=len(requests), expected_bytes=len(payload), received_bytes=received_bytes,
          complete_requests=complete_requests)
    _require(len(decisions) == 1 and decisions[0]["verdict"] == expected, f"Unexpected decision for {name}.")
    if expected == "BLOCK":
        # Receiver bytes are observed separately because termination can follow body delivery.
        _require(decisions[0]["enforcement"]["termination"] == "CONFIRMED", "Synthetic BLOCK was unconfirmed.")
    else:
        _require(child.returncode == 0, f"The synthetic {name} transfer failed.")
        _require(len(requests) == complete_requests == 1 and received_bytes == len(payload),
                 f"Receiver did not get the complete synthetic {name} payload.")


def _probe_worker(origin_token):
    """Child-only helper for checking a real thread token, handle isolation and timeout."""
    data = json.load(sys.stdin.buffer)
    with impersonate_origin(origin_token) as scope:
        if "sentinel" in data:
            signal_event = ctypes.WinDLL("kernel32").SetEvent
            signal_event.argtypes = (wintypes.HANDLE,)
            signal_event.restype = wintypes.BOOL
            signal_event(data["sentinel"])
        if "descendant" in data:
            code = ("import json, os, sys, time, psutil; from pathlib import Path; "
                    "Path(sys.argv[1]).write_text(json.dumps([os.getpid(), psutil.Process().create_time()]), "
                    "encoding='ascii'); time.sleep(30)")
            with subprocess.Popen([sys.executable, "-E", "-s", "-B", "-c", code, data["descendant"]],
                                  stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, close_fds=True) as child:
                child.wait(timeout=35)
        _emit(scope=_scope_fields(scope), synthetic_env_inherited=SYNTHETIC_ENV in os.environ)


def _check_worker(origin, scope, root, run_worker):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateEventW.argtypes = (wintypes.LPVOID, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR)
    kernel.CreateEventW.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.CloseHandle.restype = wintypes.BOOL
    sentinel = kernel.CreateEventW(None, True, False, None)
    if not sentinel:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        os.set_handle_inheritable(sentinel, True)
        os.environ[SYNTHETIC_ENV] = "only-a-synthetic-test-value"
        payload = json.dumps({"sentinel": sentinel}).encode("ascii")
        response = json.loads(run_worker(SCRIPT, payload, origin.token_handle, 5))
        _require(response["scope"] == _scope_fields(scope), "Worker impersonation scope did not match the origin.")
        _require(not response["synthetic_env_inherited"], "The worker inherited the synthetic secret.")
        _require(kernel.WaitForSingleObject(sentinel, 0) == 258, "An unrelated inheritable event reached the worker.")
        _emit(case="impersonation-and-inheritance", **response)
    finally:
        os.environ.pop(SYNTHETIC_ENV, None)
        kernel.CloseHandle(sentinel)

    witness = root / "descendant.json"
    payload = json.dumps({"descendant": str(witness)}).encode("ascii")
    try:
        run_worker(SCRIPT, payload, origin.token_handle, 5)
    except subprocess.TimeoutExpired:
        _require(witness.is_file(), "Worker timed out before a descendant could be verified.")
        pid, created = json.loads(witness.read_text(encoding="ascii"))
        try:
            survivor = psutil.Process(pid).create_time() == created
        except psutil.NoSuchProcess:
            survivor = False
        _require(not survivor, "The synthetic worker descendant survived timeout cleanup.")
        _emit(case="worker-tree-timeout", descendant_removed=True)
    else:
        raise RuntimeError("Synthetic worker did not time out.")


def _check_peer(args, scope):
    try:
        proc = psutil.Process(args.origin_pid)
        created = proc.create_time()
    except psutil.AccessDenied:
        _emit(case="external-origin", accepted=False, reason="PROCESS_IDENTITY_UNAVAILABLE")
        _require(args.expect == "foreign", "The expected same-context curl could not be verified.")
        return
    try:
        with open_origin(proc.pid, created, scope):
            _require(args.expect == "same", "The external curl should have been outside the supported scope.")
    except OriginUnavailable as exc:
        _emit(case="external-origin", accepted=False, reason=exc.reason)
        _require(args.expect == "foreign" and proc.is_running() and exc.reason in {
            "TOKEN_CONTEXT_UNSUPPORTED", "PROCESS_IDENTITY_UNAVAILABLE", "ORIGIN_TOKEN_UNAVAILABLE"},
                 "External curl did not produce the expected verified context result.")
    else:
        _emit(case="external-origin", accepted=True)


def _check_source(curl, scope, source, expected_reason):
    status = curl_agent._policy_snapshot({"applicable_policies": [_policy("REPORT_ONLY")]})
    with _holding_origin(curl) as child:
        proc = psutil.Process(child.pid)
        with open_origin(proc.pid, proc.create_time(), scope) as origin:
            results = curl_agent._inspect_verified_origin(
                [curl_agent.Upload(str(source), "127.0.0.1:1")], status, origin)
    _require(len(results) == 1, "Unexpected number of source probe results.")
    result = results[0]
    _emit(case="source-authorization", reason=result["reason"], inspected=result["inspected"],
          digest_present=bool(result.get("file_hash_sha256")))
    _require(result["reason"] == expected_reason and not result["inspected"]
             and not result.get("file_hash_sha256") and not result.get("matched_rule_ids"),
             "The synthetic source did not produce the expected inaccessible or unsupported result.")


def _run(args, parser):
    if args.inspect_worker:
        if not args.origin_token or args.output:
            parser.error("Invalid synthetic worker invocation.")
        _probe_worker(args.origin_token)
        return
    curl = Path(os.environ["SystemRoot"]) / "System32" / "curl.exe"
    if not curl.is_file():
        parser.error("The native System32 curl.exe is required.")
    if args.hold_origin:
        with _holding_origin(curl) as child:
            _emit(case="held-origin", pid=child.pid)
            try:
                time.sleep(110)
            except KeyboardInterrupt:
                pass
        return
    try:
        scope = watcher_scope()
    except OriginUnavailable as exc:
        _emit(case="watcher", supported=False, reason=exc.reason)
        raise SystemExit(2) from None
    _emit(case="watcher", **_scope_fields(scope), venv=sys.prefix != sys.base_prefix)
    if args.origin_pid is not None:
        _check_peer(args, scope)
        return
    if args.check_source is not None:
        if not args.check_source.is_absolute() or args.check_source.name.lower() != "curl-runtime-denied.txt":
            parser.error("Use an absolute path to a synthetic file named curl-runtime-denied.txt.")
        _check_source(curl, scope, args.check_source, args.expect_reason)
        return

    from curl_worker import run_inspection_worker

    with tempfile.TemporaryDirectory(prefix="curl-runtime-check-") as directory:
        root = Path(directory)
        with _serve(Receiver()) as receiver:
            for name, action, expected in (("clean", "BLOCK", "ALLOW"), ("blocked", "BLOCK", "BLOCK"),
                                           ("report", "REPORT_ONLY", "LOG")):
                _transfer(curl, receiver, root, scope, name, action, expected)
        with _holding_origin(curl) as child:
            proc = psutil.Process(child.pid)
            with open_origin(proc.pid, proc.create_time(), scope) as origin:
                _check_worker(origin, scope, root, run_inspection_worker)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--hold-origin", action="store_true", help="Hold an ordinary loopback curl for a peer scope check.")
    mode.add_argument("--origin-pid", type=int, help="Check the live PID printed by a --hold-origin instance.")
    mode.add_argument("--check-source", type=Path, help="Probe a deliberately inaccessible synthetic file.")
    mode.add_argument("--inspect-worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--origin-token", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--expect", choices=("same", "foreign"), default="same")
    parser.add_argument("--expect-reason", default="UNREADABLE")
    parser.add_argument("--output", type=Path, help="Write synthetic observations to a new JSONL file.")
    args = parser.parse_args(argv)
    if sys.platform != "win32":
        parser.error("This fixture requires Windows.")
    if args.output is None:
        _run(args, parser)
    else:
        with args.output.open("x", encoding="utf-8") as output, redirect_stdout(output):
            _run(args, parser)


if __name__ == "__main__":
    main()
