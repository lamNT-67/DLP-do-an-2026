"""Mocked checks for the verified Curl inspection path and failure boundaries."""

import io
import json
import subprocess
import sys
import unittest
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import Mock, patch

import psutil

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import curl_agent as curl
import content_inspection
from dev_tools import make_samples
from policy_utils import get_exit_point_status


DESTINATION = "receiver.example:443"
UPLOAD = curl.Upload(str(Path(__file__).resolve()), DESTINATION)
STATUS = get_exit_point_status([{
    "policy_id": 42, "exit_points": [curl.EXIT_POINT], "action": "BLOCK",
    "content_rules": [{"id": 1, "rule_type": "REGEX", "pattern": "sensitive"}],
}], curl.EXIT_POINT)


def engine_reply(_script, payload, _token_handle, _timeout):
    request = json.loads(payload)
    results = curl._inspect_uploads(request["uploads"], request["status"])
    return json.dumps({"request_id": request["request_id"], "results": results})


class VerifiedProcessTests(unittest.TestCase):
    def setUp(self):
        self.proc = Mock(pid=100, info={"name": "curl.exe"})
        self.proc.create_time.return_value = 123
        self.proc.is_running.return_value = True
        self.proc.cmdline.return_value = ["curl.exe", "-T", UPLOAD.path, "https://receiver.example/"]
        self.scope = object()
        self.record = Mock()
        self.legacy_worker = Mock()
        self.terminate = Mock()
        self.monitor = curl.CurlMonitor(self.record, self.legacy_worker, self.terminate,
                                        windows_scope=self.scope)

    def test_identity_failure_never_reads_metadata_or_controls_process(self):
        with patch.object(curl, "open_origin", side_effect=curl.OriginUnavailable("PROCESS_IDENTITY_UNAVAILABLE")):
            for _ in range(curl.METADATA_ATTEMPTS):
                self.monitor.poll(STATUS, [self.proc])
        self.proc.cmdline.assert_not_called()
        self.proc.cwd.assert_not_called()
        self.proc.suspend.assert_not_called()
        self.terminate.assert_not_called()
        self.legacy_worker.assert_not_called()
        self.assertEqual(self.record.call_args.args[2]["reason"], "PROCESS_IDENTITY_UNAVAILABLE")

    def test_failed_worker_never_uses_legacy_worker_and_resumes_target(self):
        errors = (curl.OriginUnavailable("ORIGIN_IMPERSONATION_FAILED"),
                  subprocess.TimeoutExpired("worker", 5), curl.WorkerCleanupUnconfirmed("unconfirmed"))
        reasons = ("ORIGIN_IMPERSONATION_FAILED", "INSPECTION_TIMEOUT", "WORKER_CLEANUP_UNCONFIRMED")
        for index, (error, reason) in enumerate(zip(errors, reasons)):
            with self.subTest(reason=reason):
                self.proc.create_time.return_value = 123 + index
                origin = Mock()
                with (patch.object(curl, "open_origin", return_value=origin) as open_origin,
                      patch.object(curl, "_inspect_verified_origin", side_effect=error)):
                    self.monitor.poll(STATUS, [self.proc])
                open_origin.assert_called_once_with(self.proc.pid, 123 + index, self.scope)
                origin.close_token.assert_called_once()
                origin.close.assert_called_once()
                self.assertEqual(self.record.call_args.args[2]["reason"], reason)
        self.assertEqual(self.proc.resume.call_count, len(errors))
        self.legacy_worker.assert_not_called()
        self.terminate.assert_not_called()

    def test_failed_resume_retains_process_pin_but_not_token(self):
        origin = Mock()
        self.proc.resume.side_effect = [psutil.AccessDenied(self.proc.pid), None]
        with (patch.object(curl, "open_origin", return_value=origin),
              patch.object(curl, "_inspect_verified_origin", return_value=[curl._diagnostic("INSPECTION_ERROR")])):
            self.monitor.poll(STATUS, [self.proc])
        origin.close_token.assert_called_once()
        origin.close.assert_not_called()
        self.assertTrue(self.monitor.pending_resume)
        self.assertEqual(self.monitor.retry_resumes(), {})
        origin.close.assert_called_once()
        self.assertFalse(self.monitor.pending_resume)

    def test_engine_log_followed_by_block_reaches_termination(self):
        status = get_exit_point_status([{
            **STATUS["policies"][0],
            "content_rules": [{"id": 1, "rule_type": "REGEX", "pattern": r"sensitive-\d+",
                               "severity": "MEDIUM"}],
        }], curl.EXIT_POINT)
        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            logged = root / "logged.txt"
            blocked = root / "blocked.txt"
            logged.write_bytes(b"sensitive-1")
            blocked.write_bytes(b"sensitive-1 sensitive-2")
            self.proc.cmdline.return_value = ["curl.exe", "-T", str(logged), "https://receiver.example/",
                                              "-T", str(blocked), "https://receiver.example/"]

            def reply(*args):
                payload = engine_reply(*args)
                self.assertEqual([r["verdict"] for r in json.loads(payload)["results"]], ["LOG", "BLOCK"])
                return payload

            self.terminate.return_value = curl.Termination(True, "CONFIRMED")
            with (patch.object(curl, "open_origin", return_value=Mock()),
                  patch.object(curl, "run_inspection_worker", side_effect=reply) as worker):
                self.monitor.poll(status, [self.proc])

        worker.assert_called_once()
        self.proc.suspend.assert_called_once()
        self.terminate.assert_called_once_with(self.proc)
        self.proc.resume.assert_not_called()
        self.assertFalse(self.monitor.pending_resume)
        self.record.assert_called_once()
        _, upload, result, enforcement = self.record.call_args.args
        self.assertEqual(upload.path, str(blocked))
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertEqual(enforcement["termination"], "CONFIRMED")


class VerifiedWorkerTests(unittest.TestCase):
    def test_response_binds_to_job_and_rejects_out_of_scope_results(self):
        verdict = {"verdict": "BLOCK", "reason": "CONTENT_MATCH", "inspected": True,
                   "file_hash_sha256": "a" * 64, "matched_rule_ids": [1],
                   "confidence_score": "HIGH", "policy_id": 42, "policy_action": "BLOCK"}

        def reply(_path, payload, token_handle, timeout):
            self.assertEqual(token_handle, 7)
            self.assertEqual(timeout, curl.INSPECTION_TIMEOUT)
            request = json.loads(payload)
            self.assertEqual(request.keys(), {"request_id", "uploads", "status"})
            return json.dumps({"request_id": request["request_id"], "results": [verdict]})

        with patch.object(curl, "run_inspection_worker", side_effect=reply):
            self.assertEqual(curl._inspect_verified_origin([UPLOAD], STATUS, Mock(token_handle=7)), [verdict])
            for field, value in (("policy_id", 10), ("policy_action", "REPORT_ONLY"),
                                 ("matched_rule_ids", [99]), ("matched_rule_ids", [True]),
                                 ("file_hash_sha256", "secret"), ("verdict", []), ("pid", 100)):
                with self.subTest(field=field), patch.dict(verdict, {field: value}):
                    with self.assertRaises(ValueError):
                        curl._inspect_verified_origin([UPLOAD], STATUS, Mock(token_handle=7))
        with patch.object(curl, "run_inspection_worker", return_value=json.dumps({"request_id": "stale", "results": [verdict]})):
            with self.assertRaises(ValueError):
                curl._inspect_verified_origin([UPLOAD], STATUS, Mock(token_handle=7))

    def test_report_only_attribution_cannot_block(self):
        block_policy = STATUS["policies"][0]
        report_policy = {**block_policy, "policy_id": 43, "action": "REPORT_ONLY"}
        status = get_exit_point_status([block_policy, report_policy], curl.EXIT_POINT)
        result = {"verdict": "BLOCK", "reason": "CONTENT_MATCH", "inspected": True,
                  "file_hash_sha256": "a" * 64, "matched_rule_ids": [1],
                  "confidence_score": "HIGH", "policy_id": 43, "policy_action": "REPORT_ONLY"}

        def reply(_script, payload, _token_handle, _timeout):
            return json.dumps({"request_id": json.loads(payload)["request_id"], "results": [result]})

        with patch.object(curl, "run_inspection_worker", side_effect=reply):
            with self.assertRaises(ValueError):
                curl._inspect_verified_origin([UPLOAD], status, Mock(token_handle=7))

    def test_response_cardinality_and_block_ends_the_batch(self):
        logged = {"verdict": "LOG", "reason": "CONTENT_MATCH", "inspected": True,
                  "file_hash_sha256": "a" * 64, "matched_rule_ids": [1],
                  "confidence_score": "LOW", "policy_id": 42, "policy_action": "BLOCK"}
        blocked = {**logged, "verdict": "BLOCK", "confidence_score": "HIGH"}
        for results in ([], [logged], [blocked, logged], [logged, logged, blocked]):
            with self.subTest(results=results):
                def reply(_script, payload, _token_handle, _timeout):
                    return json.dumps({"request_id": json.loads(payload)["request_id"], "results": results})

                with patch.object(curl, "run_inspection_worker", side_effect=reply):
                    with self.assertRaises(ValueError):
                        curl._inspect_verified_origin([UPLOAD, UPLOAD], STATUS, Mock(token_handle=7))

    def run_child(self):
        output = io.StringIO()
        request = {"request_id": "a" * 32, "uploads": [UPLOAD], "status": STATUS}
        with (patch.object(curl.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(json.dumps(request).encode()))),
              redirect_stdout(output)):
            self.assertEqual(curl._run_origin_worker(7), 0)
        return json.loads(output.getvalue())

    def test_worker_enters_impersonation_before_calling_inspection(self):
        trace = []

        @contextmanager
        def impersonate(token_handle):
            self.assertEqual(token_handle, 7)
            trace.append("impersonate")
            try:
                yield
            finally:
                trace.append("revert")

        def inspect(_uploads, _status, *, verify_origin):
            self.assertTrue(verify_origin)
            trace.append("inspect")
            return [curl._diagnostic("UNVERIFIED_SOURCE_PATH")]

        with (patch.object(curl, "impersonate_origin", side_effect=impersonate),
              patch.object(curl, "_inspect_uploads", side_effect=inspect)):
            self.assertEqual(self.run_child()["results"][0]["reason"], "UNVERIFIED_SOURCE_PATH")
        self.assertEqual(trace, ["impersonate", "inspect", "revert"])

    def test_impersonation_failure_prevents_any_inspection(self):
        error = curl.OriginUnavailable("ORIGIN_IMPERSONATION_FAILED")
        with (patch.object(curl, "impersonate_origin", side_effect=error),
              patch.object(curl, "_inspect_uploads") as inspect):
            self.assertEqual(self.run_child()["error"], "ORIGIN_IMPERSONATION_FAILED")
            inspect.assert_not_called()

    def test_authorized_context_denial_preserves_unreadable_disposition(self):
        with patch.object(curl, "_open_local_file", side_effect=PermissionError) as open_file:
            result, = curl._inspect_uploads([UPLOAD], STATUS, verify_origin=True)
        open_file.assert_called_once_with(UPLOAD.path, verify_origin=True)
        self.assertEqual((result["verdict"], result["reason"]), ("BLOCK", "UNREADABLE"))
        self.assertFalse(result["inspected"])
        self.assertIsNone(result["file_hash_sha256"])

    def test_unverified_volume_does_not_use_primary_identity_open(self):
        with (patch.object(curl, "verify_drive", side_effect=curl.PathContextUnavailable("UNVERIFIED_SOURCE_PATH")),
              patch.object(curl.Path, "open") as open_file):
            result, = curl._inspect_uploads([UPLOAD], STATUS, verify_origin=True)
        open_file.assert_not_called()
        self.assertEqual(result, curl._diagnostic("UNVERIFIED_SOURCE_PATH"))


class EngineWorkerResultTests(unittest.TestCase):
    def inspect_source(self, filename, data, status=STATUS):
        with TemporaryDirectory() as directory:
            source = Path(directory).resolve() / filename
            source.write_bytes(data)
            with patch.object(curl, "run_inspection_worker", side_effect=engine_reply):
                result, = curl._inspect_verified_origin([curl.Upload(str(source), DESTINATION)], status,
                                                        Mock(token_handle=7))
        return result

    def test_block_policy_accepts_low_confidence_log(self):
        result = self.inspect_source("low.txt", b"sensitive")
        self.assertEqual((result["verdict"], result["reason"], result["confidence_score"], result["policy_action"]),
                         ("LOG", "CONTENT_MATCH", "LOW", "BLOCK"))

    def test_block_policy_accepts_too_large_log(self):
        with patch.multiple(content_inspection, MAX_FILE_BYTES=32, BLOCK_TOO_LARGE=False):
            result = self.inspect_source("oversize.pdf", b"%PDF-1.7\n" + b"x" * 64)
        self.assertEqual((result["verdict"], result["reason"], result["policy_action"], result["inspection_limit"]),
                         ("LOG", "TOO_LARGE", "BLOCK", "TOO_LARGE"))

    def test_block_policy_accepts_configured_encrypted_log(self):
        data = make_samples.mark_zip_encrypted(make_samples.build_zip({"records.txt": "sensitive"}))
        with patch.object(content_inspection, "BLOCK_ENCRYPTED", False):
            result = self.inspect_source("encrypted.zip", data)
        self.assertEqual((result["verdict"], result["reason"], result["policy_action"]),
                         ("LOG", "ENCRYPTED_CONTENT", "BLOCK"))

    def test_accepts_critical_content_match_from_both_policy_actions(self):
        for action, verdict in (("BLOCK", "BLOCK"), ("REPORT_ONLY", "LOG")):
            with self.subTest(action=action):
                status = get_exit_point_status([{
                    **STATUS["policies"][0], "action": action,
                    "content_rules": [{"id": 1, "rule_type": "REGEX", "pattern": r"sensitive-\d+",
                                       "severity": "CRITICAL"}],
                }], curl.EXIT_POINT)
                result = self.inspect_source("critical.txt", b"sensitive-1 sensitive-2", status)
                self.assertEqual((result["verdict"], result["confidence_score"], result["policy_action"]),
                                 (verdict, "CRITICAL", action))


if __name__ == "__main__":
    unittest.main()
