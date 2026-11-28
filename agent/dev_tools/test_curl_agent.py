"""Curl DLP parser, policy and enforcement tests with synthetic inputs."""

import json
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import psutil

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import curl_agent as curl
import log_writer
from curl_windows import LogonScope
from policy_utils import get_exit_point_status


URL = "https://receiver.example/import"
DESTINATION = "receiver.example:443"
MARKER = "CURL_SYNTHETIC_MARKER"


def policy(policy_id=7, action="BLOCK", marker=MARKER, **settings):
    return {
        "policy_id": policy_id, "name": "Synthetic policy", "action": action, "exit_points": [curl.EXIT_POINT],
        "file_types": [], "allowed_files": [], "allowed_locations": [],
        "content_rules": [{"id": policy_id, "rule_name": "Synthetic", "rule_type": "REGEX",
                           "pattern": marker, "severity": "HIGH", "category": "INTERNAL_DOC"}],
        **settings,
    }


def status(*policies):
    return get_exit_point_status(policies, curl.EXIT_POINT)


class ParserTests(unittest.TestCase):
    def test_common_file_arguments_preserve_windows_paths(self):
        filename = r"C:\My Files\sample.txt"
        for args in [
            ["-T", filename], ["-T" + filename], ["--upload-file", filename],
            ["--upload-file=" + filename], ["-sST" + filename],
            ["-F", "part=@" + filename], ["-Fpart=<" + filename],
            ["--form", 'file=@"' + filename + '";type=text/plain;filename=test.txt'],
            ["-d", "@" + filename], ["-d@" + filename], ["--data", "@" + filename],
            ["--data-ascii", "@" + filename], ["--data-binary=@" + filename],
        ]:
            with self.subTest(args=args):
                self.assertEqual(curl.parse_uploads(["curl.exe", *args, URL]),
                                 [curl.Upload(filename, DESTINATION)])

    def test_curl_form_quotes_and_escaped_backslashes(self):
        value = r'file=@"C:\\My Files\\report, a;b.txt";type=text/plain'
        self.assertEqual(curl.parse_uploads(["curl.exe", "-F", value, URL]),
                         [curl.Upload(r"C:\My Files\report, a;b.txt", DESTINATION)])

    def test_repeated_forms_data_and_paired_put_uploads(self):
        for args in (["-F", "a=@first.txt", "--form=b=<second.txt"],
                     ["-d@first.txt", "--data-binary", "@second.txt", "-d", "k=literal"]):
            self.assertEqual(curl.parse_uploads(["curl.exe", *args, URL]),
                             [curl.Upload("first.txt", DESTINATION), curl.Upload("second.txt", DESTINATION)])
        args = ["curl.exe", "-Tfirst.txt", "--url", URL, "-Tsecond.txt", "--", "http://other.example/"]
        self.assertEqual(curl.parse_uploads(args), [curl.Upload("first.txt", DESTINATION),
                                                    curl.Upload("second.txt", "other.example:80")])

    def test_get_head_download_and_literal_body(self):
        for args in [
            [], [URL], ["-I", URL], ["--head", URL], ["--request", "GET", URL],
            ["-o", "@output.txt", URL], ["-O", URL], ["--data-raw", "@not-a-file", URL],
            ["--data", "email=@literal", URL], ["--data-binary", "literal", URL],
            ["--form-string", "text=@literal", URL], ["-F", "note=plain text", URL],
            ["-G", "-d", "key=value", URL], ["--version"], ["--help", "upload"],
        ]:
            with self.subTest(args=args):
                self.assertEqual(curl.parse_uploads(["curl.exe", *args]), [])

    def test_custom_http_method_does_not_disable_file_body(self):
        for method in ("POST", "GET", "HEAD"):
            args = ["curl.exe", "-X", method, "-d@body.txt", "--url", URL]
            self.assertEqual(curl.parse_uploads(args), [curl.Upload("body.txt", DESTINATION)])

    def test_destination_drops_secrets_and_consumes_unrelated_option_values(self):
        args = ["curl.exe", "--user", "user:password", "-H", "https://not-the-destination",
                "-T", "file.txt", "HTTPS://user:password@Receiver.Example:9443/a?token=secret#fragment"]
        self.assertEqual(curl.parse_uploads(args), [curl.Upload("file.txt", "receiver.example:9443")])
        self.assertEqual(curl.parse_uploads(["curl.exe", "-d@a", "http://[::1]:9000/"]),
                         [curl.Upload("a", "[::1]:9000")])

    def test_unsupported_is_reported_as_coverage(self):
        cases = [
            (["-K", "secret-config", URL], "UNSUPPORTED_OPTION"),
            (["--next", "-T", "file.txt", URL], "UNSUPPORTED_OPTION"),
            (["-L", "-T", "file.txt", URL], "UNSUPPORTED_OPTION"),
            (["--url-query", "@query.txt", URL], "UNSUPPORTED_OPTION"),
            (["--data-urlencode", "@file.txt", URL], "UNSUPPORTED_OPTION"),
            (["--json", "@file.txt", URL], "UNSUPPORTED_OPTION"),
            (["-T"], "MISSING_OPTION_VALUE"),
            (["-T", "file[1-2].txt", URL], "UPLOAD_GLOB"),
            (["-T", "file.txt", URL + "/{a,b}"], "URL_GLOB"),
            (["-F", "file=@a.txt,b.txt", URL], "UNSUPPORTED_FORM"),
            (["-F", "text=ok;headers=@secret", URL], "UNSUPPORTED_FORM"),
            (["-d@a", "-F", "field=@b", URL], "UNSUPPORTED_REQUEST_MODE"),
            (["-I", "-T", "file.txt", URL], "UNSUPPORTED_REQUEST_MODE"),
            (["-G", "-d@query.txt", URL], "UNSUPPORTED_REQUEST_MODE"),
            (["-T", "a", "-T", "b", URL], "AMBIGUOUS_DESTINATION"),
            (["-d@a", URL, "http://other.example"], "AMBIGUOUS_DESTINATION"),
            (["-T", "file.txt", "sftp://other.example"], "UNSUPPORTED_DESTINATION"),
            (["-T", "file.txt", "receiver.example"], "UNSUPPORTED_DESTINATION"),
            (["-T", "file.txt", "http://x:123456"], "UNSUPPORTED_DESTINATION"),
        ]
        for args, reason in cases:
            with self.subTest(args=args), self.assertRaisesRegex(curl.UnsupportedSyntax, f"^{reason}$"):
                curl.parse_uploads(["curl.exe", *args])

    def test_streams_and_nonlocal_windows_paths_are_unsupported(self):
        for arg in ("-", ".", r"C:file.txt", r"\\host\share\secret.txt",
                    r"\\.\pipe\stream", r"C:\folder\NUL.txt", r"C:\file.txt:stream"):
            with self.subTest(arg=arg), self.assertRaisesRegex(curl.UnsupportedSyntax, "UNSUPPORTED_SOURCE_PATH"):
                curl.parse_uploads(["curl.exe", "-T", arg, URL])


class MonitorTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="curl-dlp ")
        self.addCleanup(directory.cleanup)
        self.cwd = Path(directory.name)
        self.path = self.cwd / "source file.txt"
        self.path.write_text(MARKER, encoding="utf-8")
        self.proc = Mock(pid=1122)
        self.proc.info = {"name": "CURL.EXE"}
        self.proc.cmdline.return_value = ["curl.exe", "-T", self.path.name, URL]
        self.proc.cwd.return_value = directory.name
        self.proc.create_time.return_value = 1234
        self.proc.is_running.return_value = True
        self.record = Mock()
        self.terminate = Mock(return_value=curl.Termination(True, "CONFIRMED"))
        self.monitor = curl.CurlMonitor(self.record, curl._inspect_uploads, self.terminate)

    def observe(self, *policies, record_index=-1):
        self.monitor.poll(status(*policies), [self.proc])
        return self.record.call_args_list[record_index].args[1:]

    def test_block_on_resolved_relative_path_uses_winning_policy(self):
        upload, result, enforcement = self.observe(policy(3, "REPORT_ONLY"), policy())
        self.assertEqual(upload, curl.Upload(str(self.path), DESTINATION))
        self.assertEqual((result["verdict"], result["reason"], result["policy_id"], result["matched_rule_ids"]),
                         ("BLOCK", "CONTENT_MATCH", 7, [7]))
        self.assertEqual(enforcement, {"suspension": "SUSPENDED", "resume": "PROCESS_EXITED",
                                      "termination": "CONFIRMED", "termination_attempted": True})
        self.proc.suspend.assert_called_once()
        self.terminate.assert_called_once_with(self.proc)
        self.proc.resume.assert_not_called()

    def test_monitor_only_does_not_suspend_or_terminate(self):
        _, result, enforcement = self.observe(policy(action="REPORT_ONLY"))
        self.assertEqual((result["verdict"], result["policy_id"]), ("LOG", 7))
        self.assertEqual(enforcement["suspension"], "NOT_ATTEMPTED")
        self.proc.suspend.assert_not_called()
        self.terminate.assert_not_called()

    def test_clean_upload_resumes_before_recording(self):
        self.path.write_text("public material", encoding="utf-8")
        self.record.side_effect = lambda *_: self.proc.resume.assert_called_once()
        _, result, enforcement = self.observe(policy())
        self.assertEqual((result["verdict"], result["reason"]), ("ALLOW", "CLEAN"))
        self.assertEqual(enforcement["resume"], "RESUMED")
        self.terminate.assert_not_called()

    def test_multiple_files_inspected_once_and_strongest_decision_selected(self):
        clean = self.cwd / "public.txt"
        clean.write_text("public material", encoding="utf-8")
        self.proc.cmdline.return_value = [
            "curl.exe", "-F", "a=@" + clean.name, "-F", "b=@" + self.path.name,
            "-F", "again=@" + self.path.name, URL,
        ]
        with patch.object(curl, "inspect_file", wraps=curl.inspect_file) as inspect:
            upload, result, _ = self.observe(policy())
        self.assertEqual(inspect.call_count, 2)
        self.assertEqual((upload.path, result["verdict"]), (str(self.path), "BLOCK"))
        self.terminate.assert_called_once()

    def test_file_type_scope_and_policy_local_exceptions(self):
        for condition in [
            {"allowed_files": [self.path.name]}, {"allowed_locations": [str(self.cwd)]},
            {"allowed_locations": [DESTINATION]}, {"file_types": [{"extension": "pdf"}]},
        ]:
            with self.subTest(condition=condition):
                self.monitor.seen.clear()
                exempt_block = policy(**condition)
                log_policy = policy(11, "REPORT_ONLY")
                _, result, _ = self.observe(exempt_block, log_policy)
                self.assertEqual((result["verdict"], result["policy_id"]), ("LOG", 11))
                self.monitor.seen.clear()
                _, result, _ = self.observe(log_policy, exempt_block)
                self.assertEqual((result["verdict"], result["policy_id"]), ("LOG", 11))
        self.terminate.assert_not_called()

    def test_ruleless_block_respects_file_type_scope(self):
        _, result, _ = self.observe(policy(content_rules=[], file_types=[{"extension": "pdf"}]))
        self.assertEqual((result["verdict"], result["reason"]), ("ALLOW", "OUT_OF_SCOPE"))
        self.terminate.assert_not_called()

    def test_unreadable_uses_existing_policy_semantics(self):
        self.path.unlink()
        for action, verdict in (("BLOCK", "BLOCK"), ("REPORT_ONLY", "LOG")):
            self.monitor.seen.clear()
            _, result, _ = self.observe(policy(action=action))
            self.assertEqual((result["verdict"], result["reason"], result["inspected"]),
                             (verdict, "UNREADABLE", False))

    def test_engine_failure_is_coverage_and_resumes(self):
        with patch.object(curl, "inspect_file", side_effect=RuntimeError("SENSITIVE EXCEPTION")):
            _, result, enforcement = self.observe(policy())
        self.assertEqual(result, {"verdict": None, "reason": "INSPECTION_ERROR", "inspected": False})
        self.assertEqual(enforcement["resume"], "RESUMED")
        self.terminate.assert_not_called()

    def test_inspection_timeout_is_coverage_and_resumes(self):
        self.monitor.inspect_uploads = Mock(side_effect=subprocess.TimeoutExpired("worker", 5))
        _, result, enforcement = self.observe(policy())
        self.assertEqual(result["reason"], "INSPECTION_TIMEOUT")
        self.assertEqual(enforcement["resume"], "RESUMED")
        self.proc.resume.assert_called_once()
        self.terminate.assert_not_called()

    def test_non_regular_file_is_a_coverage_limit(self):
        self.proc.cmdline.return_value = ["curl.exe", "-T", str(self.cwd), URL]
        _, result, enforcement = self.observe(policy())
        self.assertEqual(result["reason"], "NON_REGULAR_FILE")
        self.assertEqual(enforcement["resume"], "RESUMED")
        self.terminate.assert_not_called()

    def test_exit_before_suspend_is_not_a_termination(self):
        self.proc.suspend.side_effect = psutil.NoSuchProcess(self.proc.pid)
        _, result, enforcement = self.observe(policy())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertEqual(enforcement["suspension"], "PROCESS_EXITED")
        self.assertEqual(enforcement["termination"], "EXITED_BEFORE_TERMINATION")
        self.assertFalse(enforcement["termination_attempted"])
        self.terminate.assert_not_called()
        self.proc.resume.assert_not_called()

    def test_suspension_denied_and_termination_denied_are_distinct(self):
        self.proc.suspend.side_effect = psutil.AccessDenied(self.proc.pid)
        self.terminate.side_effect = psutil.AccessDenied(self.proc.pid)
        _, result, enforcement = self.observe(policy())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertEqual(enforcement["suspension"], "SUSPEND_FAILED")
        self.assertEqual(enforcement["termination"], "TERMINATION_FAILED")
        self.proc.resume.assert_not_called()

    def test_unconfirmed_termination_resumes_process(self):
        self.terminate.return_value = curl.Termination(True, "TERMINATION_UNCONFIRMED")
        _, result, enforcement = self.observe(policy())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertEqual(enforcement["termination"], "TERMINATION_UNCONFIRMED")
        self.assertTrue(enforcement["termination_attempted"])
        self.proc.resume.assert_called_once()

    def test_resume_failure_is_retried_even_if_policy_is_removed(self):
        self.proc.resume.side_effect = [psutil.AccessDenied(self.proc.pid), None]
        _, _, enforcement = self.observe(policy(marker="NO_MATCH"))
        self.assertEqual(enforcement["resume"], "RESUME_FAILED")
        self.monitor.poll(status(), [])
        self.assertEqual(self.record.call_args.args[2]["reason"], "RESUME_RETRY")
        self.assertEqual(self.record.call_args.args[3]["resume"], "RESUMED")
        self.assertFalse(self.monitor.pending_resume)

    def test_unavailable_cwd_does_not_use_watchers_directory(self):
        self.proc.cwd.side_effect = psutil.AccessDenied(self.proc.pid)
        for _ in range(curl.METADATA_ATTEMPTS - 1):
            self.monitor.poll(status(policy()), [self.proc])
            self.record.assert_not_called()
        _, result, _ = self.observe(policy())
        self.assertEqual(result["reason"], "WORKING_DIRECTORY_UNAVAILABLE")
        self.proc.suspend.assert_not_called()

    def test_absolute_windows_path_needs_no_cwd(self):
        self.proc.cmdline.return_value = ["curl.exe", "-d", "@" + str(self.path), URL]
        _, result, _ = self.observe(policy())
        self.assertEqual(result["verdict"], "BLOCK")
        self.proc.cwd.assert_not_called()

    def test_unsupported_and_plain_curl_are_never_suspended(self):
        self.proc.cmdline.return_value = ["curl.exe", "-K", "private-config", URL]
        self.observe(policy(content_rules=[]))
        self.assertEqual(self.record.call_args.args[2]["reason"], "UNSUPPORTED_OPTION")
        self.monitor.seen.clear()
        self.proc.cmdline.return_value = ["curl.exe", "-I", "-o", "output.txt", URL]
        self.monitor.poll(status(policy(content_rules=[])), [self.proc])
        self.assertEqual(self.record.call_count, 1)
        self.proc.suspend.assert_not_called()
        self.terminate.assert_not_called()

    def test_poll_deduplicates_process_identity_and_skips_other_process_names(self):
        other = Mock()
        other.info = {"name": "other.exe"}
        for _ in range(2):
            self.monitor.poll(status(policy()), [other, self.proc])
        other.cmdline.assert_not_called()
        self.record.assert_called_once()
        self.proc.create_time.return_value = 1235
        self.observe(policy())
        self.assertEqual(self.record.call_count, 2)


class TerminationTests(unittest.TestCase):
    def test_native_termination_checks_and_closes_the_same_handle(self):
        cases = [
            ([0], True, False, "EXITED_BEFORE_TERMINATION"),
            ([258, 0], False, True, "EXITED_DURING_TERMINATION_ATTEMPT"),
            ([258, 258], False, True, "TERMINATION_FAILED"),
            ([258, 258], True, True, "TERMINATION_UNCONFIRMED"),
            ([258, 0], True, True, "CONFIRMED"),
        ]
        for states, requested, attempted, outcome in cases:
            with self.subTest(outcome=outcome):
                proc = Mock(pid=1122)
                proc.is_running.return_value = True
                kernel = Mock()
                kernel.OpenProcess.return_value = 333
                kernel.WaitForSingleObject.side_effect = states
                kernel.TerminateProcess.return_value = requested
                with patch.object(curl.ctypes, "WinDLL", return_value=kernel, create=True):
                    self.assertEqual(curl._terminate_windows(proc), curl.Termination(attempted, outcome))
                kernel.CloseHandle.assert_called_once_with(333)
                self.assertEqual(kernel.TerminateProcess.call_count, int(attempted))
                self.assertTrue(all(call.args[0] == 333 for call in kernel.WaitForSingleObject.call_args_list))


class JournalTests(unittest.TestCase):
    def test_managed_journal_records_the_verified_logon_for_local_notification(self):
        scope = LogonScope(b"test-sid", 0x100000002, 3, 0x2000)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.log"
            with patch.object(log_writer, "LOG_FILE", path):
                for context in (scope, None):
                    journal = curl.CurlJournal("test-host", None, windows_scope=context)
                    journal.record((100, 1), curl.Upload("sample.txt", DESTINATION),
                                   {"verdict": "BLOCK", "policy_action": "BLOCK"},
                                   {"termination": "CONFIRMED", "termination_attempted": True})
            managed, standalone = map(json.loads, path.read_text(encoding="utf-8").splitlines())
        self.assertEqual((managed["source"]["session_id"], managed["source"]["logon_luid"]),
                         (3, "0000000100000002"))
        self.assertEqual(managed["action_taken"], standalone["action_taken"])
        self.assertNotIn("session_id", standalone["source"])
        self.assertNotIn("logon_luid", standalone["source"])

    def test_local_first_and_validated_delivery_without_sensitive_values(self):
        for outcome, ack, action in [
            ("CONFIRMED", 42, "BLOCKED_KILL"),
            ("CONFIRMED", OSError("secret"), "BLOCKED_KILL"),
            ("EXITED_BEFORE_TERMINATION", True, "LOGGED"),
            ("TERMINATION_FAILED", None, "LOGGED"),
            ("TERMINATION_UNCONFIRMED", None, "LOGGED"),
        ]:
            with self.subTest(outcome=outcome, ack=ack), tempfile.TemporaryDirectory() as directory:
                log_path = Path(directory) / "local.log"
                delivery_path = Path(directory) / "delivery.log"
                delivered = threading.Event()

                def report(payload, *, require_ack):
                    self.assertTrue(require_ack)
                    self.assertTrue(log_path.is_file())
                    if isinstance(ack, Exception):
                        raise ack
                    return ack

                def delivery(*args, **kwargs):
                    log_writer.write_curl_delivery_status(*args, **kwargs)
                    delivered.set()

                client = Mock()
                client.send_report.side_effect = report
                with patch.multiple(log_writer, LOG_FILE=log_path, CURL_DELIVERY_FILE=delivery_path), \
                        patch.object(curl, "write_curl_delivery_status", side_effect=delivery):
                    journal = curl.CurlJournal("test-host", client)
                    upload = curl.Upload(str(Path(directory) / "source.txt"), DESTINATION)
                    fields = {"verdict": "BLOCK", "reason": "CONTENT_MATCH", "inspected": True,
                              "policy_id": 7, "policy_action": "BLOCK", "confidence_score": "HIGH",
                              "matched_rule_ids": [7], "file_hash_sha256": None}
                    journal.record((100, 1), upload, fields,
                                   {"termination": outcome, "resume": "NOT_NEEDED"})
                    self.assertTrue(delivered.wait(3))
                    self.assertTrue(journal.close())

                event = json.loads(log_path.read_text())
                delivery_status = json.loads(delivery_path.read_text())
                payload = client.send_report.call_args.args[0]
                self.assertEqual((event["action_taken"], event["policy_id"], event["exit_point_type"]),
                                 (action, 7, curl.EXIT_POINT))
                self.assertEqual((event["content_inspection"]["reason"], event["enforcement"]["termination"]),
                                 ("CONTENT_MATCH", outcome))
                self.assertEqual(payload["action_taken"], action)
                self.assertEqual((payload["exit_point_type"], payload["policy_id"]), (curl.EXIT_POINT, 7))
                self.assertEqual(payload["file_path"], "source.txt")
                self.assertEqual(delivery_status["event_id"], event["event_id"])
                self.assertFalse(event["reported_to_server"])
                self.assertNotIn("secret", json.dumps([event, payload, delivery_status]))
                expected = ("ACKNOWLEDGED", 42) if ack == 42 else ("UNACKNOWLEDGED", None)
                self.assertEqual((delivery_status["status"], delivery_status.get("server_log_id")), expected)

    def test_coverage_and_allow_events_remain_local(self):
        with patch.object(curl, "write_log_event") as write:
            journal = curl.CurlJournal("test-host", Mock())
            journal.record((100, 1), None, curl._diagnostic("UNSUPPORTED_OPTION"), None)
            journal.record((100, 1), curl.Upload("file.txt", DESTINATION),
                           {"verdict": "ALLOW", "reason": "CLEAN"}, {"resume": "RESUMED"})
            self.assertEqual([(call.args[3], call.args[8], call.kwargs["report_configured"])
                              for call in write.call_args_list],
                             [("coverage", "LOGGED", False), ("allowed", "ALLOWED", False)])
            journal.client.send_report.assert_not_called()
            self.assertTrue(journal.close())

    def test_coverage_record_does_not_claim_inspection_or_report_enforcement(self):
        with patch.object(curl, "write_log_event") as write:
            journal = curl.CurlJournal("test-host", Mock())
            upload = curl.Upload("opaque.txt", DESTINATION)
            result = {"verdict": "ALLOW", "reason": "NOT_INSPECTABLE", "inspected": False,
                      "coverage": True}
            journal.record((100, 1), upload, result, {"resume": "RESUMED"})
            journal.record((100, 1), upload, {**result, "verdict": "BLOCK"},
                           {"termination": "CONFIRMED"})
            self.assertTrue(journal.close())
        self.assertEqual([(call.args[3], call.args[8], call.kwargs["report_configured"])
                          for call in write.call_args_list],
                         [("coverage", "LOGGED", False), ("coverage", "LOGGED", False)])
        journal.client.send_report.assert_not_called()

    @staticmethod
    def _record_block(journal, upload=None, rule_ids=()):
        journal.record(
            (100, 1), upload,
            {"verdict": "BLOCK", "reason": "CONTENT_MATCH", "inspected": True,
             "policy_id": 7, "policy_action": "BLOCK", "confidence_score": "HIGH",
             "matched_rule_ids": rule_ids, "file_hash_sha256": None},
            {"termination": "CONFIRMED", "resume": "NOT_NEEDED"},
        )

    def test_report_limits_use_utf8_bytes_and_preserve_local_evidence(self):
        client = Mock()
        client.send_report.return_value = 12
        basename = "\u00e9" * 250
        destination = "a" * 251 + ":443"
        rule_ids = list(range(100, 200))
        with patch.object(curl, "write_log_event") as local, \
                patch.object(curl, "write_curl_delivery_status"):
            journal = curl.CurlJournal("test-host", client)
            self._record_block(journal, curl.Upload(basename, destination), rule_ids)
            self._record_block(journal, curl.Upload(basename + "x", destination + "0"), rule_ids)
            self.assertTrue(journal.close())

        first, second = [call.args[0] for call in client.send_report.call_args_list]
        self.assertEqual((first["file_path"], first["destination_value"]), (basename, destination))
        self.assertEqual((second["file_path"], second["destination_value"]), (None, None))
        self.assertEqual(len(",".join(map(str, second["matched_rule_ids"]))), 255)
        self.assertEqual(second["matched_rule_ids"], rule_ids[:64])
        self.assertEqual(local.call_args.args[6]["file_path"], basename + "x")
        self.assertEqual(local.call_args.args[7]["matched_rule_ids"], rule_ids)

    def test_local_event_write_failure_is_correlated_with_later_ack(self):
        client = Mock()
        client.send_report.return_value = 12
        with patch.object(curl, "write_log_event", side_effect=OSError("private value")), \
                patch.object(curl, "write_curl_delivery_status") as delivery, \
                patch.object(curl.sys, "stderr") as stderr:
            journal = curl.CurlJournal("test-host", client)
            self._record_block(journal)
            self.assertTrue(journal.close())
        failure, ack = delivery.call_args_list
        self.assertEqual(failure.args[0], ack.args[0])
        self.assertEqual((failure.args[1], ack.args[1]), ("LOCAL_EVENT_FAILED", "ACKNOWLEDGED"))
        self.assertEqual(ack.kwargs["server_log_id"], 12)
        self.assertIn(failure.args[0], str(stderr.write.call_args_list))
        self.assertNotIn("private value", str(stderr.write.call_args_list))

    def test_shutdown_deadline_leaves_in_flight_report_and_starts_no_next_report(self):
        started, release = threading.Event(), threading.Event()

        def send(*args, **kwargs):
            started.set()
            if not release.wait(3):
                raise TimeoutError
            return 12

        client = Mock()
        client.send_report.side_effect = send
        with patch.object(curl, "write_log_event"), \
                patch.object(curl, "write_curl_delivery_status") as delivery, \
                patch.object(curl.sys, "stderr") as stderr:
            journal = curl.CurlJournal("test-host", client)
            try:
                self._record_block(journal)
                self.assertTrue(started.wait(2))
                self._record_block(journal)
                self.assertFalse(journal.close(timeout=0.01))
                self.assertIn("Report drain timed out", str(stderr.write.call_args_list))
            finally:
                release.set()
                self.assertTrue(journal.close())
        client.send_report.assert_called_once()
        delivery.assert_called_once()


class PolicyTests(unittest.TestCase):
    def test_refresh_keeps_last_status_when_server_unavailable(self):
        client = Mock()
        client.get_policy.side_effect = [{"applicable_policies": [policy()]}, None,
                                         {"applicable_policies": []}]
        policies = curl.CurlPolicy(client)
        policies.refresh()
        self.assertTrue(policies.status["is_governed"])
        with patch("sys.stderr"):
            policies.refresh()
        self.assertTrue(policies.status["is_governed"])
        policies.refresh()
        self.assertFalse(policies.status["is_governed"])


if __name__ == "__main__":
    unittest.main()
