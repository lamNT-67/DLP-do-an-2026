"""Managed enrollment and cooperative watcher shutdown without host changes."""

import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import contextmanager, nullcontext, redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import curl_agent as curl
import curl_lifecycle
from curl_windows import LogonScope


class ManagedEnrollmentTests(unittest.TestCase):
    def test_reopens_partial_config_and_uses_existing_device_token(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config.ini"
            path.write_text("[incomplete", encoding="utf-8")
            complete = "[agent]\napi_token = issued-token\nhostname = LAB\nserver_url = https://dlp.test/api\n"
            stop = Mock()
            stop.is_set.return_value = False
            stop.wait.side_effect = lambda _: path.write_text(complete, encoding="utf-8-sig")
            with patch.object(curl.CurlPolicyClient, "register") as register:
                client = curl._wait_for_enrollment(path, stop)
            stop.wait.assert_called_once_with(curl.ENROLLMENT_RETRY_INTERVAL)
            register.assert_not_called()
            self.assertEqual((client.hostname, client.api_token), ("LAB", "issued-token"))
            self.assertEqual(path.read_text(encoding="utf-8-sig"), complete)

    def test_stop_interrupts_token_wait_before_monitor_creation(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config.ini"
            stop = threading.Event()
            with (patch.object(stop, "wait", side_effect=lambda _: stop.set()) as wait,
                  patch.object(curl, "_watch") as watch):
                outcome = curl.run_managed_watcher(path, object(), stop)
            self.assertFalse(path.exists())
        wait.assert_called_once_with(curl.ENROLLMENT_RETRY_INTERVAL)
        watch.assert_not_called()
        self.assertEqual(outcome, {"pending_resumes": 0, "worker_cleanup_confirmed": True,
                                   "report_drained": True, "runtime_failed": False})

    def test_enrollment_deadline_yields_a_retryable_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config.ini"
            stop = threading.Event()
            with (patch.object(curl, "ENROLLMENT_TIMEOUT", 0),
                  patch.object(curl, "_watch") as watch):
                outcome = curl.run_managed_watcher(path, object(), stop)
        watch.assert_not_called()
        self.assertTrue(outcome["runtime_failed"])
        self.assertEqual(outcome["pending_resumes"], 0)
        self.assertTrue(outcome["worker_cleanup_confirmed"])

    def test_cannot_select_unscoped_legacy_runtime(self):
        with self.assertRaises(ValueError), patch.object(curl, "_wait_for_enrollment") as wait:
            curl.run_managed_watcher(None, None, threading.Event())
        wait.assert_not_called()


class ManagedShutdownTests(unittest.TestCase):
    def run_watcher(self, *, pending=(), confirmed=True, drained=True, failure=None, cleanup=None):
        scope = object()
        stop = threading.Event()
        monitor = Mock(pending_resume=dict(pending), worker_cleanup_confirmed=confirmed)
        monitor.poll.side_effect = failure or (lambda *_, **__: stop.set())
        monitor.cleanup.side_effect = cleanup
        client = Mock(hostname="LAB")
        journal = Mock()
        journal.close.return_value = drained
        journal.reports.unfinished_tasks = 0
        with (patch.object(curl, "_wait_for_enrollment", return_value=client),
              patch.object(curl, "CurlMonitor", return_value=monitor) as factory,
              patch.object(curl, "CurlJournal", return_value=journal),
              patch.object(curl.threading, "Thread")):
            try:
                return curl.run_managed_watcher(None, scope, stop)
            finally:
                factory.assert_called_once_with(journal.record, windows_scope=scope)
                monitor.cleanup.assert_called_once()
                journal.close.assert_called_once()

    def test_unresolved_resume_survives_otherwise_clean_stop(self):
        outcome = self.run_watcher(pending=[((100, 1), object())])
        self.assertEqual(outcome, {"pending_resumes": 1, "worker_cleanup_confirmed": True,
                                   "report_drained": True, "runtime_failed": False})

    def test_report_deadline_independent_of_verified_process_cleanup(self):
        outcome = self.run_watcher(drained=False)
        self.assertEqual(outcome, {"pending_resumes": 0, "worker_cleanup_confirmed": True,
                                   "report_drained": False, "runtime_failed": False})

    def test_poll_exception_runs_final_cleanup_and_marks_runtime_failed(self):
        outcome = self.run_watcher(failure=RuntimeError(), confirmed=False)
        self.assertTrue(outcome["runtime_failed"])
        self.assertFalse(outcome["worker_cleanup_confirmed"])

    def test_cleanup_exception_never_returns_a_success_outcome(self):
        with self.assertRaises(OSError):
            self.run_watcher(cleanup=OSError())

    def test_worker_cleanup_confirmation_controls_managed_receipt(self):
        scope = LogonScope(b"test-user", 1234, 5, 8192)
        poll = curl.CurlMonitor.poll
        for worker_error, reason, confirmed in (
            (subprocess.TimeoutExpired("inspection worker", curl.INSPECTION_TIMEOUT), "INSPECTION_TIMEOUT", True),
            (curl.WorkerCleanupUnconfirmed(), "WORKER_CLEANUP_UNCONFIRMED", False),
        ):
            with self.subTest(reason=reason):
                proc = Mock(pid=200, info={"name": "curl.exe"})
                proc.create_time.return_value = 123
                proc.cmdline.return_value = ["curl.exe", "-T", str(Path(__file__).resolve()), "https://dlp.test/"]
                origin = Mock(token_handle=17)
                journal = Mock()
                journal.close.return_value = True
                journal.reports.unfinished_tasks = 0
                policy = Mock(status={"is_governed": True, "effective_action": "BLOCK"})
                registry = Mock()
                registry.maintenance.return_value = ""
                registry.current_generation.return_value = True
                stop_requested_by_monitor = []

                def poll_once(monitor, status, *, stop):
                    poll(monitor, status, [proc], stop=stop)
                    stop_requested_by_monitor.append(stop.is_set())
                    stop.set()

                with (patch.object(curl_lifecycle, "_Registry", return_value=registry),
                      patch.object(curl_lifecycle, "_singleton", return_value=nullcontext(True)),
                      patch.object(curl, "_wait_for_enrollment", return_value=Mock(hostname="LAB")),
                      patch.object(curl, "CurlPolicy", return_value=policy),
                      patch.object(curl, "CurlJournal", return_value=journal),
                      patch.object(curl.CurlMonitor, "poll", poll_once),
                      patch.object(curl, "open_origin", return_value=origin),
                      patch.object(curl, "run_inspection_worker", side_effect=worker_error) as run_worker,
                      curl_lifecycle.ManagedInstance(scope) as instance):
                    outcome = curl.run_managed_watcher(None, scope, instance.stop)
                    state = instance.finish(outcome)

                run_worker.assert_called_once()
                proc.suspend.assert_called_once()
                proc.resume.assert_called_once()
                origin.close.assert_called_once()
                self.assertEqual(journal.record.call_args.args[2]["reason"], reason)
                self.assertEqual(stop_requested_by_monitor, [not confirmed])
                self.assertEqual(outcome, {"pending_resumes": 0, "worker_cleanup_confirmed": confirmed,
                                           "report_drained": True, "runtime_failed": False})
                self.assertEqual(state, "complete" if confirmed else "incomplete")
                registry.write.assert_called_once()
                receipt = registry.write.call_args.args[0]
                self.assertEqual((receipt["state"], receipt["worker_cleanup_confirmed"]), (state, confirmed))
                if confirmed:
                    registry.clear_logon.assert_called_once_with(instance.name, receipt["instance"])
                else:
                    registry.clear_logon.assert_not_called()

    def test_scope_failure_keeps_foreign_pid_out_of_journal(self):
        record = Mock()
        monitor = curl.CurlMonitor(record, windows_scope=object())
        proc = Mock(pid=200, info={"name": "curl.exe"})
        proc.create_time.return_value = 123
        with patch.object(curl, "open_origin", side_effect=curl.OriginUnavailable("TOKEN_CONTEXT_UNSUPPORTED")):
            for _ in range(curl.METADATA_ATTEMPTS):
                monitor.poll({"is_governed": True}, [proc])
        self.assertEqual(record.call_args.args[:2], ((None, None), None))
        proc.cmdline.assert_not_called()


class StandaloneEntryTests(unittest.TestCase):
    def invoke(self, guard, watch):
        config = "[agent]\napi_token = issued-token\nhostname = LAB\nserver_url = https://dlp.test/api\n"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.ini"
            path.write_text(config, encoding="utf-8")
            with (patch.object(curl.sys, "platform", "win32"), patch.object(curl.signal, "signal"),
                  redirect_stderr(StringIO()), redirect_stdout(StringIO()),
                  patch.object(curl_lifecycle, "standalone_admission", return_value=guard),
                  patch.object(curl, "_watch", watch)):
                return curl.main(["--config", str(path)])

    def test_deployed_or_duplicate_standalone_never_polls(self):
        watch = Mock()
        self.assertNotEqual(self.invoke(nullcontext(False), watch), 0)
        watch.assert_not_called()

    def test_standalone_holds_admission_through_cleanup(self):
        steps = []

        @contextmanager
        def admission():
            steps.append("entered")
            try:
                yield True
            finally:
                steps.append("released")

        def watch(*args):
            steps.append("cleanup")
            return {"pending_resumes": 1}

        self.assertNotEqual(self.invoke(admission(), watch), 0)
        self.assertEqual(steps, ["entered", "cleanup", "released"])

    def test_verified_worker_does_not_request_standalone_admission(self):
        with (patch.object(curl.sys, "platform", "win32"),
              patch.object(curl, "_run_origin_worker", return_value=0) as worker,
              patch.object(curl_lifecycle, "standalone_admission") as guard):
            self.assertEqual(curl.main(["--inspect-worker", "--origin-token", "7"]), 0)
        worker.assert_called_once_with(7)
        guard.assert_not_called()


if __name__ == "__main__":
    unittest.main()
