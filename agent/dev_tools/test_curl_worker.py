"""Windows smoke tests for the worker launcher using disposable local processes."""

import ctypes
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import ExitStack
from ctypes import wintypes
from pathlib import Path
from unittest.mock import patch

import psutil

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from curl_worker import WorkerCleanupUnconfirmed, run_inspection_worker


def _file_path(handle):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    path_for_handle = kernel.GetFinalPathNameByHandleW
    path_for_handle.argtypes = (wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD)
    path_for_handle.restype = wintypes.DWORD
    path = ctypes.create_unicode_buffer(32768)
    size = path_for_handle(handle, path, len(path), 0)
    if not 0 < size < len(path):
        return None
    return path.value.removeprefix("\\\\?\\")


def _child(handle):
    request = json.load(sys.stdin.buffer)
    if request["mode"] == "inspect":
        print("synthetic parser warning", file=sys.stderr)
        json.dump({"allowed": _file_path(handle), "unrelated": _file_path(request["unrelated"]),
                   "secret": os.environ.get("DLP_TEST_SECRET"),
                   "cwd": os.getcwd(), "prefix": sys.prefix}, sys.stdout)
    elif request["mode"] == "timeout":
        child = subprocess.Popen([sys.executable, "-B", "-c", "import time; time.sleep(30)"],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
        process = psutil.Process(child.pid)
        Path(request["receipt"]).write_text(json.dumps([child.pid, process.create_time()]), encoding="utf-8")
        time.sleep(30)
    elif request["mode"] == "overflow":
        sys.stdout.buffer.write(b"x" * 8192)


def _cleanup_folder(folder):
    deadline = time.monotonic() + 1
    while True:
        try:
            folder.cleanup()
            return
        except OSError as exc:
            # Windows can briefly retain a file handle during process rundown.
            if exc.winerror not in (32, 145) or time.monotonic() >= deadline:
                raise
            time.sleep(0.02)


@unittest.skipUnless(sys.platform == "win32", "Win32 worker launcher")
class WindowsWorkerTests(unittest.TestCase):
    def setUp(self):
        import msvcrt

        folder = tempfile.TemporaryDirectory()
        self.addCleanup(_cleanup_folder, folder)
        self.folder = Path(folder.name).resolve()
        self.files = ExitStack()
        self.addCleanup(self.files.close)
        # An ordinary file handle stands in for the token to test only the
        # launcher allowlist. The runtime checks impersonation separately.
        allowed = self.files.enter_context((self.folder / "allowed").open("w+b"))
        self.allowed_handle = msvcrt.get_osfhandle(allowed.fileno())

    def run_worker(self, mode, timeout=5, **fields):
        payload = json.dumps({"mode": mode, **fields}).encode()
        return run_inspection_worker(Path(__file__).resolve(), payload, self.allowed_handle, timeout)

    def test_allowlisted_handle_and_controlled_environment(self):
        import msvcrt

        unrelated = self.files.enter_context((self.folder / "unrelated").open("w+b"))
        unrelated_handle = msvcrt.get_osfhandle(unrelated.fileno())
        os.set_handle_inheritable(unrelated_handle, True)
        self.addCleanup(os.set_handle_inheritable, unrelated_handle, False)
        with patch.dict(os.environ, {"DLP_TEST_SECRET": "must not inherit"}):
            result = json.loads(self.run_worker("inspect", unrelated=unrelated_handle))
        self.assertEqual(Path(result["allowed"]), self.folder / "allowed")
        self.assertNotEqual(result["unrelated"], str(self.folder / "unrelated"))
        self.assertIsNone(result["secret"])
        self.assertEqual(Path(result["cwd"]), Path(__file__).resolve().parent)
        self.assertEqual(Path(result["prefix"]), Path(sys.prefix))
        self.assertFalse(os.get_handle_inheritable(self.allowed_handle))

    def test_timeout_reaps_worker_and_descendant(self):
        receipt = self.folder / "descendant.json"
        with self.assertRaises(subprocess.TimeoutExpired):
            self.run_worker("timeout", timeout=3, receipt=str(receipt))
        pid, created = json.loads(receipt.read_text(encoding="utf-8"))
        try:
            still_exists = psutil.Process(pid).create_time() == created
        except psutil.NoSuchProcess:
            still_exists = False
        self.assertFalse(still_exists)

    def test_output_is_capped_and_borrowed_handle_survives(self):
        with patch("curl_worker.MAX_OUTPUT_BYTES", 512):
            with self.assertRaisesRegex((ValueError, OSError), "Inspection worker"):
                self.run_worker("overflow")
        self.assertEqual(Path(_file_path(self.allowed_handle)), self.folder / "allowed")

    def test_reap_requires_native_confirmation(self):
        with patch("curl_worker._active_processes", side_effect=OSError("accounting failed")):
            with self.assertRaises(WorkerCleanupUnconfirmed):
                self.run_worker("inspect", unrelated=0)

    def test_failed_job_attribute_prevents_launch(self):
        receipt = self.folder / "descendant.json"
        with patch("curl_worker._JOB_LIST", 0xFFFFFFFF):
            with self.assertRaises(OSError):
                self.run_worker("timeout", receipt=str(receipt))
        self.assertFalse(receipt.exists())


if __name__ == "__main__":
    if sys.argv[1:3] == ["--inspect-worker", "--origin-token"]:
        _child(int(sys.argv[3]))
    else:
        unittest.main()
