"""Regression tests for curl argument and per-operand inspection coverage."""

import hashlib
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import content_inspection
import curl_agent as curl
from policy_utils import get_exit_point_status


URL = "https://example.test/"
DESTINATION = "example.test:443"
MARKER = b"SYNTHETIC_SECRET"


def policy_status(**overrides):
    policy = {
        "policy_id": 42, "exit_points": [curl.EXIT_POINT], "action": "BLOCK",
        "content_rules": [{"id": 1, "rule_type": "REGEX", "pattern": MARKER.decode("ascii"),
                           "severity": "HIGH", "category": "INTERNAL_DOC"}],
    }
    policy.update(overrides)
    return get_exit_point_status([policy], curl.EXIT_POINT)


class CurlArgumentCoverageTests(unittest.TestCase):
    def test_file_backed_headers_are_unsupported_with_or_without_file_body(self):
        cases = (["-H", "@headers.txt"], ["-H@-"], ["--header", "@headers.txt"],
                 ["--header=@headers.txt"], ["-H", "@headers.txt", "-T", "data.txt"])
        for options in cases:
            with self.subTest(options=options):
                with self.assertRaisesRegex(curl.UnsupportedSyntax, "^FILE_BACKED_HEADER$"):
                    curl.parse_uploads(["curl.exe", *options, URL])

    def test_literal_headers_preserve_body_classification(self):
        argv = ["curl.exe", "-H", "X-Tag: @sample.txt", "--header=Expect:", URL]
        self.assertEqual(curl.parse_uploads(argv), [])
        self.assertEqual(curl.parse_uploads([*argv, "-T", "body.txt"]),
                         [curl.Upload("body.txt", DESTINATION)])

    def test_form_filenames_preserve_unicode_whitespace_and_trim_ascii_padding(self):
        plain = "\u00a0report.txt\u00a0"
        quoted = " report, version.txt "
        argv = ["curl.exe", "-F", f"a=@ \t{plain}\t ",
                "-F", f'b=< \t"{quoted}" \t; type=text/plain', URL]
        self.assertEqual(curl.parse_uploads(argv),
                         [curl.Upload(plain, DESTINATION), curl.Upload(quoted, DESTINATION)])


class CurlFileCoverageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.safe = self.directory / "safe.txt"
        self.safe.write_bytes(b"ordinary file contents")
        self.marked = self.directory / "marked.txt"
        self.marked.write_bytes(MARKER)

    def inspect(self, source, **overrides):
        return curl._inspect_uploads([curl.Upload(str(source), DESTINATION)], policy_status(**overrides))[0]

    def observe(self, *sources, inspect_uploads=curl._inspect_uploads):
        record = Mock()
        terminate = Mock(return_value=curl.Termination(True, "CONFIRMED"))
        monitor = curl.CurlMonitor(record, inspect_uploads=inspect_uploads, terminate=terminate)
        process = Mock(pid=123)
        process.info = {"name": "curl.exe"}
        process.is_running.return_value = True
        process.create_time.return_value = 12
        args = ["curl.exe", URL]
        for source in sources:
            args += ["-d", "@" + str(source)]
        process.cmdline.return_value = args
        monitor.poll(policy_status(), [process])
        return [call.args[1:] for call in record.call_args_list], process, terminate

    def test_content_and_digest_use_one_open_file(self):
        original_open = Path.open
        with patch.object(Path, "open", autospec=True, side_effect=original_open) as source_open:
            result = self.inspect(self.marked)
        self.assertEqual((result["verdict"], result["file_hash_sha256"]),
                         ("BLOCK", hashlib.sha256(MARKER).hexdigest()))
        source_open.assert_called_once_with(self.marked, "rb")

    def test_file_exception_does_not_open_source(self):
        with patch.object(curl, "_open_local_file") as source_open:
            result = self.inspect(self.marked, allowed_files=[self.marked.name])
        self.assertEqual((result["verdict"], result["inspected"], result["reason"]),
                         ("ALLOW", False, "ALLOWED_FILE"))
        source_open.assert_not_called()

    @unittest.skipUnless(sys.platform == "win32", "Windows path aliases")
    def test_nonlocal_volume_is_classified_before_filesystem_access(self):
        with patch.object(curl, "_is_local_windows_volume", return_value=False), \
                patch.object(Path, "lstat") as stat_source, patch.object(Path, "open") as source_open:
            result = self.inspect(self.marked)
        self.assertEqual(result, curl._diagnostic("NON_LOCAL_SOURCE_VOLUME"))
        stat_source.assert_not_called()
        source_open.assert_not_called()

    @unittest.skipUnless(sys.platform == "win32", "Windows path aliases")
    def test_reparse_ancestor_is_rejected_before_opening(self):
        original_lstat = Path.lstat

        def lstat(path):
            attributes = original_lstat(path)
            if path == self.directory:
                return SimpleNamespace(st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT)
            return attributes

        with patch.object(Path, "lstat", autospec=True, side_effect=lstat), \
                patch.object(Path, "open") as source_open:
            result = self.inspect(self.marked)
        self.assertEqual(result, curl._diagnostic("UNSUPPORTED_SOURCE_ALIAS"))
        source_open.assert_not_called()

    @unittest.skipUnless(sys.platform == "win32", "Windows path aliases")
    def test_handle_path_mismatch_is_rejected_before_reading(self):
        with patch.object(curl, "_windows_final_path", return_value=str(self.safe)), \
                patch.object(content_inspection, "_read_stream") as read:
            result = self.inspect(self.marked)
        self.assertEqual(result, curl._diagnostic("UNSUPPORTED_SOURCE_ALIAS"))
        read.assert_not_called()

    def test_uninspectable_operand_keeps_coverage_beside_clean_result(self):
        image = self.directory / "no-ocr.png"
        image.write_bytes(b"\x89PNG\r\n\x1a\n" + bytes(30))
        records, process, terminate = self.observe(self.safe, image)
        self.assertEqual([(upload.path, result["verdict"], result["reason"], result.get("coverage"))
                          for upload, result, _ in records],
                         [(str(self.safe), "ALLOW", "CLEAN", None),
                          (str(image), "ALLOW", "NOT_INSPECTABLE", True)])
        self.assertFalse(records[1][1]["inspected"])
        process.resume.assert_called_once()
        terminate.assert_not_called()

    def test_partial_text_read_is_separate_from_allow_disposition(self):
        self.safe.write_bytes(b"a" * (curl.MAX_TEXT_READ_BYTES + 1))
        records, _, terminate = self.observe(self.safe)
        self.assertEqual(len(records), 1)
        _, result, _ = records[0]
        self.assertEqual((result["verdict"], result["reason"], result["coverage"], result["inspected"]),
                         ("ALLOW", "PARTIAL_CONTENT_INSPECTION", True, True))
        terminate.assert_not_called()

    def test_unreadable_block_and_coverage_are_both_recorded(self):
        missing = self.directory / "missing.txt"
        records, _, terminate = self.observe(missing)
        self.assertEqual([(upload.path, result["verdict"], result["reason"], result.get("coverage"))
                          for upload, result, _ in records],
                         [(str(missing), "BLOCK", "UNREADABLE", None),
                          (str(missing), "BLOCK", "UNREADABLE", True)])
        terminate.assert_called_once()

    def test_timeout_and_worker_error_record_each_operand(self):
        failures = ((subprocess.TimeoutExpired("worker", 5), "INSPECTION_TIMEOUT"),
                    (RuntimeError("private exception"), "INSPECTION_ERROR"))
        for exception, reason in failures:
            with self.subTest(reason=reason):
                records, process, terminate = self.observe(
                    self.safe, self.marked, inspect_uploads=Mock(side_effect=exception))
                self.assertEqual([(upload.path, result) for upload, result, _ in records],
                                 [(str(source), curl._diagnostic(reason))
                                  for source in (self.safe, self.marked)])
                process.resume.assert_called_once()
                terminate.assert_not_called()

    def test_early_block_records_skipped_operand(self):
        records, _, terminate = self.observe(self.marked, self.safe)
        self.assertEqual((records[0][0].path, records[0][1]["verdict"]), (str(self.marked), "BLOCK"))
        self.assertEqual((records[1][0].path, records[1][1]),
                         (str(self.safe), curl._diagnostic("NOT_SCANNED_AFTER_BLOCK")))
        terminate.assert_called_once()

    def test_short_worker_results_record_incomplete_operand(self):
        first = self.inspect(self.safe)
        records, process, terminate = self.observe(
            self.safe, self.marked, inspect_uploads=Mock(return_value=[first]))
        self.assertEqual((records[1][0].path, records[1][1]),
                         (str(self.marked), curl._diagnostic("INSPECTION_INCOMPLETE")))
        process.resume.assert_called_once()
        terminate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
