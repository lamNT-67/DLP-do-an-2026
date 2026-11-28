"""Worker cleanup regressions and Windows smoke tests with disposable processes."""

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
from unittest.mock import Mock, call, patch

import psutil

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import curl_worker
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


class WorkerCleanupTests(unittest.TestCase):
    """Exercise real tracking and cleanup logic with deterministic Windows calls."""

    def setUp(self):
        self.kernel = Mock()
        self.kernel.QueryInformationJobObject.side_effect = self.query_job
        self.kernel.GetProcessId.side_effect = lambda handle: handle - 100
        self.kernel.OpenProcess.side_effect = lambda rights, inherit, pid: pid + 100
        self.kernel.IsProcessInJob.side_effect = self.in_job
        self.kernel.WaitForSingleObject.return_value = 0
        self.kernel.TerminateJobObject.return_value = True
        self.snapshots = [(1,)]
        self.accounting = [(1, 0)]
        self.job = 90
        self.resources = ExitStack()
        self.addCleanup(self.resources.close)
        self.resources.callback(self.kernel.CloseHandle, 101)
        self.members = curl_worker._JobMembers(self.kernel, self.job, self.resources)
        self.members.add_worker(101)
        self.now = 100.0

    def query_job(self, job, info_class, buffer, size, returned):
        self.assertEqual(job, self.job)
        if info_class == 3:
            pids = self.snapshots.pop(0) if len(self.snapshots) > 1 else self.snapshots[0]
            listing = ctypes.cast(buffer, ctypes.POINTER(curl_worker._JobProcessIds)).contents
            listing.NumberOfAssignedProcesses = len(pids)
            listing.NumberOfProcessIdsInList = len(pids)
            listing.ProcessIdList[:len(pids)] = pids
        elif info_class == 1:
            total, active = self.accounting.pop(0) if len(self.accounting) > 1 else self.accounting[0]
            counters = ctypes.cast(buffer, ctypes.POINTER(curl_worker._JobAccounting)).contents
            counters.TotalProcesses = total
            counters.ActiveProcesses = active
        else:
            self.fail(f"Unexpected job information class {info_class}")
        return True

    def in_job(self, handle, job, result):
        self.assertEqual(job, self.job)
        ctypes.cast(result, ctypes.POINTER(wintypes.BOOL)).contents.value = handle != 102 or self.member_102
        return True

    member_102 = True

    def reap(self):
        with patch("curl_worker.time.monotonic", side_effect=lambda: self.now):
            curl_worker._reap_job(self.kernel, self.job, self.members, 101.0)

    def test_reconciles_nested_members_and_waits_every_pinned_handle(self):
        self.snapshots = [(1, 2, 3)]
        self.accounting = [(3, 2)]  # References may keep the accounting active count above zero.
        self.members.discover()
        self.reap()
        self.assertEqual(self.members.handles, {1: 101, 2: 102, 3: 103})
        opened = [args.args[2] for args in self.kernel.OpenProcess.call_args_list]
        self.assertCountEqual(opened, [2, 3])
        self.assertCountEqual([args.args[0] for args in self.kernel.WaitForSingleObject.call_args_list],
                              [101, 102, 103])
        self.kernel.TerminateJobObject.assert_called_once_with(self.job, 1)
        self.resources.close()
        self.assertCountEqual(self.kernel.CloseHandle.call_args_list, [call(101), call(102), call(103)])

    def test_late_member_is_pinned_terminated_and_waited(self):
        self.snapshots = [(1,), (1, 2)]
        self.accounting = [(2, 1), (2, 0)]
        self.reap()
        self.assertEqual(self.members.handles, {1: 101, 2: 102})
        self.assertIn(102, [args.args[0] for args in self.kernel.WaitForSingleObject.call_args_list])
        self.assertEqual(self.kernel.TerminateJobObject.call_args_list, [call(self.job, 1), call(self.job, 1)])

    def test_missing_lifetime_member_fails_even_when_job_is_empty(self):
        self.accounting = [(2, 0)]
        with self.assertRaises(WorkerCleanupUnconfirmed):
            self.reap()
        self.assertEqual(self.members.handles, {1: 101})
        self.kernel.TerminateJobObject.assert_called_with(self.job, 1)

    def test_incomplete_job_process_list_still_requests_termination(self):
        def incomplete(job, info_class, buffer, size, returned):
            self.query_job(job, info_class, buffer, size, returned)
            if info_class == 3:
                listing = ctypes.cast(buffer, ctypes.POINTER(curl_worker._JobProcessIds)).contents
                listing.NumberOfAssignedProcesses = 2
            return True

        self.kernel.QueryInformationJobObject.side_effect = incomplete
        with self.assertRaises(WorkerCleanupUnconfirmed):
            self.reap()
        self.kernel.TerminateJobObject.assert_called_once_with(self.job, 1)

    def test_reused_pid_outside_job_does_not_count_or_get_waited(self):
        self.snapshots = [(1, 2)]
        self.accounting = [(2, 0)]
        self.member_102 = False
        with self.assertRaises(WorkerCleanupUnconfirmed):
            self.reap()
        self.assertEqual(self.members.handles, {1: 101})
        self.assertNotIn(102, [args.args[0] for args in self.kernel.WaitForSingleObject.call_args_list])
        self.assertTrue(self.kernel.CloseHandle.call_args_list)
        self.assertTrue(all(args == call(102) for args in self.kernel.CloseHandle.call_args_list))

    def test_inaccessible_member_cannot_be_confirmed_by_accounting(self):
        self.snapshots = [(1, 2)]
        self.accounting = [(2, 0)]
        self.kernel.OpenProcess.side_effect = None
        self.kernel.OpenProcess.return_value = None
        with self.assertRaises(WorkerCleanupUnconfirmed):
            self.reap()
        self.kernel.TerminateJobObject.assert_called_with(self.job, 1)
        self.assertEqual(self.members.handles, {1: 101})

    def test_unsignaled_descendant_gets_only_the_remaining_deadline(self):
        self.snapshots = [(1, 2)]
        self.accounting = [(2, 0)]

        def wait(handle, ms):
            if handle == 101:
                self.now = 100.75
                return 0
            self.assertEqual(ms, 250)
            return 258

        self.kernel.WaitForSingleObject.side_effect = wait
        with self.assertRaises(WorkerCleanupUnconfirmed):
            self.reap()
        self.assertEqual(self.kernel.WaitForSingleObject.call_args_list, [call(101, 1000), call(102, 250)])
        self.resources.close()
        self.assertCountEqual(self.kernel.CloseHandle.call_args_list, [call(101), call(102)])


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
        original_reap = curl_worker._reap_job
        proof = []

        def pin_descendant(kernel, job, members, deadline):
            try:
                pid, created = json.loads(receipt.read_text(encoding="utf-8"))
                handle = kernel.OpenProcess(0x101000, False, pid)
                self.assertTrue(handle, f"Cannot observe descendant PID {pid}")
                self.files.callback(kernel.CloseHandle, handle)
                self.assertEqual(kernel.GetProcessId(handle), pid)
                self.assertEqual(psutil.Process(pid).create_time(), created)
                member = wintypes.BOOL()
                self.assertTrue(kernel.IsProcessInJob(handle, job, ctypes.byref(member)))
                self.assertTrue(member.value)
                proof.append((kernel, handle))
            finally:
                original_reap(kernel, job, members, deadline)

        with patch("curl_worker._reap_job", side_effect=pin_descendant):
            with self.assertRaises(subprocess.TimeoutExpired):
                self.run_worker("timeout", timeout=3, receipt=str(receipt))
        self.assertEqual(len(proof), 1)
        kernel, handle = proof[0]
        self.assertEqual(kernel.WaitForSingleObject(handle, 0), 0)

    def test_output_is_capped_and_borrowed_handle_survives(self):
        with patch("curl_worker.MAX_OUTPUT_BYTES", 512):
            with self.assertRaisesRegex((ValueError, OSError), "Inspection worker"):
                self.run_worker("overflow")
        self.assertEqual(Path(_file_path(self.allowed_handle)), self.folder / "allowed")

    def test_reap_requires_native_confirmation(self):
        with patch("curl_worker._job_accounting", side_effect=OSError("accounting failed")):
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
