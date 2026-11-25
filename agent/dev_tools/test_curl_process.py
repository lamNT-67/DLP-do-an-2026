"""Deterministic regression tests for curl observation and cleanup."""

import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import psutil

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import curl_agent as curl


GOVERNED = {"is_governed": True, "effective_action": "BLOCK"}
FILE = Path(__file__).resolve()
URL = "https://receiver.example/"


def mock_process(pid=100, created=123, name="curl.exe"):
    proc = Mock(pid=pid, info={"name": name})
    proc.create_time.return_value = created
    proc.is_running.return_value = True
    proc.cmdline.return_value = ["curl.exe", "-T", str(FILE), URL]
    return proc


class ProcessTests(unittest.TestCase):
    def setUp(self):
        self.record = Mock()
        self.inspect = Mock(return_value=[{"verdict": "ALLOW", "reason": "CLEAN", "inspected": True}])
        self.monitor = curl.CurlMonitor(self.record, inspect_uploads=self.inspect)

    def test_fresh_process_iter_observes_both_kinds_of_pid_reuse(self):
        # Simulate psutil returning cached Windows metadata until cache_clear runs.
        cached = []
        snapshots = iter([
            [mock_process(100, 123, "other.exe"), mock_process(101, 123)],
            [mock_process(100, 124), mock_process(101, 124)],
        ])

        def iter_processes(_attrs):
            if not cached:
                cached.extend(next(snapshots))
            return iter(cached)

        iterator = Mock(side_effect=iter_processes)
        iterator.cache_clear.side_effect = cached.clear
        with patch.object(curl.psutil, "process_iter", iterator):
            self.monitor.poll(GOVERNED)
            self.monitor.poll(GOVERNED)
        self.assertEqual(iterator.cache_clear.call_count, 2)
        self.assertEqual([event.args[0] for event in self.record.call_args_list],
                         [(101, 123), (100, 124), (101, 124)])

    def test_transient_cmdline_and_cwd_failures_recover_on_later_polls(self):
        proc = mock_process()
        argv = ["curl.exe", "-T", FILE.name, URL]
        proc.cmdline.side_effect = [psutil.AccessDenied(proc.pid), argv, argv]
        proc.cwd.side_effect = [None, str(FILE.parent)]
        for _ in range(2):
            self.monitor.poll(GOVERNED, [proc])
            proc.suspend.assert_not_called()
            self.record.assert_not_called()
        self.monitor.poll(GOVERNED, [proc])
        self.monitor.poll(GOVERNED, [proc])
        proc.suspend.assert_called_once()
        self.assertEqual(self.inspect.call_args.args[0][0].path, str(FILE))
        self.assertEqual(proc.cmdline.call_count, 3)
        self.assertFalse(self.monitor.metadata_attempts)

    def test_metadata_exhaustion_records_once_and_replacement_gets_fresh_budget(self):
        proc = mock_process()
        proc.cmdline.side_effect = psutil.AccessDenied(proc.pid)
        for _ in range(curl.METADATA_ATTEMPTS + 2):
            self.monitor.poll(GOVERNED, [proc])
        self.assertEqual(proc.cmdline.call_count, curl.METADATA_ATTEMPTS)
        self.record.assert_called_once()
        self.assertEqual(self.record.call_args.args[2]["reason"], "COMMAND_LINE_UNAVAILABLE")
        proc.suspend.assert_not_called()

        replacement = mock_process(proc.pid, created=124)
        replacement.cmdline.side_effect = [psutil.AccessDenied(proc.pid), replacement.cmdline.return_value]
        self.monitor.poll(GOVERNED, [replacement])
        self.monitor.poll(GOVERNED, [replacement])
        replacement.suspend.assert_called_once()
        self.assertEqual(self.record.call_args.args[0], (proc.pid, 124))

    def test_exited_process_during_metadata_read_is_not_retried(self):
        proc = mock_process()
        proc.cmdline.return_value = ["curl.exe", "-T", FILE.name, URL]
        proc.cwd.side_effect = psutil.NoSuchProcess(proc.pid)
        self.monitor.poll(GOVERNED, [proc])
        self.monitor.poll(GOVERNED, [proc])
        proc.cmdline.assert_called_once()
        proc.suspend.assert_not_called()
        self.record.assert_not_called()

    def test_unavailable_creation_time_records_once_without_hiding_replacement(self):
        proc = mock_process()
        proc.create_time.side_effect = psutil.AccessDenied(proc.pid)
        for _ in range(curl.METADATA_ATTEMPTS + 2):
            self.monitor.poll(GOVERNED, [proc])
        proc.cmdline.assert_not_called()
        self.record.assert_called_once()
        self.assertEqual(self.record.call_args.args[0], (proc.pid, None))
        self.assertEqual(self.record.call_args.args[2]["reason"], "PROCESS_IDENTITY_UNAVAILABLE")

        replacement = mock_process(proc.pid, created=124)
        self.monitor.poll(GOVERNED, [replacement])
        replacement.suspend.assert_called_once()
        self.assertEqual(self.record.call_args.args[0], (proc.pid, 124))

    def test_liveness_error_respects_bounded_budget_before_opening_metadata(self):
        proc = mock_process()
        proc.is_running.side_effect = psutil.AccessDenied(proc.pid)
        for _ in range(curl.METADATA_ATTEMPTS + 2):
            self.monitor.poll(GOVERNED, [proc])
        self.assertEqual(proc.is_running.call_count, curl.METADATA_ATTEMPTS)
        proc.cmdline.assert_not_called()
        self.record.assert_called_once()
        self.assertEqual(self.record.call_args.args[2]["reason"], "PROCESS_ACCESS_UNAVAILABLE")

    def test_unexpected_process_access_denial_does_not_abort_later_candidates(self):
        denied, later = mock_process(100), mock_process(101)
        original = self.monitor._handle

        def handle(proc, key, status, stop):
            if proc is denied:
                raise psutil.AccessDenied(proc.pid)
            return original(proc, key, status, stop)

        with patch.object(self.monitor, "_handle", side_effect=handle):
            self.monitor.poll(GOVERNED, [denied, later])
        later.suspend.assert_called_once()
        self.assertEqual(self.record.call_args.args[0], (later.pid, 123))

    def test_stop_requested_during_metadata_abandons_candidate_before_suspend(self):
        stop = threading.Event()
        proc = mock_process()

        def get_argv():
            stop.set()
            return proc.cmdline.return_value

        proc.cmdline.side_effect = get_argv
        self.monitor.poll(GOVERNED, [proc], stop=stop)
        proc.suspend.assert_not_called()
        self.inspect.assert_not_called()

    def test_stop_requested_during_suspend_releases_target_and_skips_remaining_candidates(self):
        stop = threading.Event()
        proc = mock_process()
        proc.suspend.side_effect = stop.set
        later = mock_process(pid=101)
        self.monitor.poll(GOVERNED, [proc, later], stop=stop)
        proc.resume.assert_called_once()
        self.assertFalse(self.monitor.pending_resume)
        self.inspect.assert_not_called()
        later.cmdline.assert_not_called()
        later.suspend.assert_not_called()

    def test_resume_recovery_retains_failed_target_until_cleanup_succeeds(self):
        proc = mock_process()
        proc.resume.side_effect = [psutil.AccessDenied(proc.pid), psutil.AccessDenied(proc.pid), None]
        self.monitor.poll(GOVERNED, [proc])
        self.assertEqual(self.record.call_args.args[3]["resume"], "RESUME_FAILED")
        self.assertEqual(self.record.call_args.args[3]["resume_error"], "ACCESS_DENIED")
        with patch.object(curl.time, "sleep") as sleep:
            self.monitor.cleanup()
        sleep.assert_called_once_with(curl.RESUME_RETRY_DELAY)
        self.assertFalse(self.monitor.pending_resume)
        self.assertEqual(self.record.call_args.args[2]["reason"], "RESUME_RETRY")
        self.assertEqual(self.record.call_args.args[3]["resume"], "RESUMED")

    def test_cleanup_is_bounded_and_distinguishes_persistent_failure_causes(self):
        denied = mock_process(100)
        denied.resume.side_effect = psutil.AccessDenied(denied.pid)
        failed = mock_process(101)
        failed.resume.side_effect = OSError("synthetic failure")
        gone = mock_process(102)
        gone.is_running.return_value = False
        self.monitor.pending_resume.update({(p.pid, 123): p for p in (denied, failed, gone)})
        with patch.object(curl.time, "sleep") as sleep:
            self.monitor.cleanup()
        self.assertEqual(sleep.call_count, curl.RESUME_CLEANUP_ATTEMPTS - 1)
        self.assertEqual(denied.resume.call_count, curl.RESUME_CLEANUP_ATTEMPTS)
        self.assertEqual(failed.resume.call_count, curl.RESUME_CLEANUP_ATTEMPTS)
        gone.resume.assert_not_called()
        self.assertEqual(set(self.monitor.pending_resume), {(100, 123), (101, 123)})
        self.assertEqual([(call.args[2]["reason"], call.args[3]) for call in self.record.call_args_list],
                         [("RESUME_RETRY", {"resume": "PROCESS_EXITED"}),
                          ("RESUME_CLEANUP_INCOMPLETE",
                           {"resume": "RESUME_FAILED", "resume_error": "ACCESS_DENIED"}),
                          ("RESUME_CLEANUP_INCOMPLETE",
                           {"resume": "RESUME_FAILED", "resume_error": "OS_ERROR"})])


if __name__ == "__main__":
    unittest.main()
