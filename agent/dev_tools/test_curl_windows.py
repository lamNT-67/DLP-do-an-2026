"""Mocked Windows origin identity, handle ownership and volume validation tests."""

import sys
import unittest
from pathlib import Path, PureWindowsPath
from unittest.mock import Mock, call, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import curl_windows as windows


SCOPE = windows.LogonScope(b"synthetic sid", 100, 1, 0x2000)
TIME = 1_700_000_000.0
FILETIME = 133_444_736_000_000_000
PROCESS, PRIMARY_TOKEN, WORKER_TOKEN, THREAD_TOKEN = 100, 101, 102, 103


class OriginTests(unittest.TestCase):
    def setUp(self):
        self.api = Mock()
        self.api.open_process.return_value = PROCESS
        self.api.creation_time.return_value = FILETIME
        self.api.image_name.return_value = r"C:\Windows\System32\curl.exe"
        self.api.is_running.return_value = True
        self.api.open_process_token.return_value = PRIMARY_TOKEN
        self.api.token_context.return_value = (SCOPE, 700)
        self.api.duplicate_origin_token.return_value = WORKER_TOKEN
        override = patch.object(windows, "_api", return_value=self.api)
        override.start()
        self.addCleanup(override.stop)

    def test_valid_origin_owns_process_and_token_only_for_its_lifetime(self):
        with windows.open_origin(500, TIME, SCOPE) as origin:
            self.assertEqual(origin.creation_filetime, FILETIME)
            self.assertEqual(origin.token_handle, WORKER_TOKEN)
            self.assertTrue(origin.is_running())
            self.api.close.assert_called_once_with(PRIMARY_TOKEN)
            self.api.open_process_token.assert_called_once_with(PROCESS, duplicate=True)
            self.api.duplicate_origin_token.assert_called_once_with(PRIMARY_TOKEN)
        origin.close()
        self.assertFalse(origin.is_running())
        self.assertIsNone(origin.token_handle)
        self.assertEqual(self.api.close.call_args_list, [call(PRIMARY_TOKEN), call(WORKER_TOKEN), call(PROCESS)])

    def test_pid_reuse_does_not_reach_token_acquisition(self):
        with self.assertRaisesRegex(windows.OriginUnavailable, "PROCESS_IDENTITY_UNAVAILABLE"):
            windows.open_origin(500, TIME - 1, SCOPE)
        self.api.open_process_token.assert_not_called()
        self.api.close.assert_called_once_with(PROCESS)

    def test_wrong_image_is_rejected_before_token_acquisition(self):
        self.api.image_name.return_value = r"C:\Windows\not-curl.exe"
        with self.assertRaisesRegex(windows.OriginUnavailable, "PROCESS_IDENTITY_UNAVAILABLE"):
            windows.open_origin(500, TIME, SCOPE)
        self.api.open_process_token.assert_not_called()
        self.api.close.assert_called_once_with(PROCESS)

    def test_inaccessible_process_is_rejected_without_an_owned_handle(self):
        self.api.open_process.side_effect = PermissionError()
        with self.assertRaisesRegex(windows.OriginUnavailable, "PROCESS_IDENTITY_UNAVAILABLE"):
            windows.open_origin(500, TIME, SCOPE)
        self.api.close.assert_not_called()

    def test_different_sid_logon_session_and_integrity_are_rejected(self):
        for scope in (SCOPE._replace(user_sid=b"other"), SCOPE._replace(authentication_id=101),
                      SCOPE._replace(session_id=2), SCOPE._replace(integrity_level=0x2100)):
            with self.subTest(scope=scope):
                self.api.reset_mock()
                self.api.token_context.return_value = (scope, 700)
                with self.assertRaisesRegex(windows.OriginUnavailable, "TOKEN_CONTEXT_UNSUPPORTED"):
                    windows.open_origin(500, TIME, SCOPE)
                self.api.duplicate_origin_token.assert_not_called()
                self.assertEqual(self.api.close.call_args_list, [call(PRIMARY_TOKEN), call(PROCESS)])

    def test_origin_token_acquisition_failure_releases_process(self):
        self.api.open_process_token.side_effect = PermissionError()
        with self.assertRaisesRegex(windows.OriginUnavailable, "ORIGIN_TOKEN_UNAVAILABLE"):
            windows.open_origin(500, TIME, SCOPE)
        self.api.duplicate_origin_token.assert_not_called()
        self.api.close.assert_called_once_with(PROCESS)

    def test_token_duplication_failure_closes_primary_token_and_process(self):
        self.api.duplicate_origin_token.side_effect = OSError()
        with self.assertRaisesRegex(windows.OriginUnavailable, "ORIGIN_TOKEN_UNAVAILABLE"):
            windows.open_origin(500, TIME, SCOPE)
        self.assertEqual(self.api.close.call_args_list, [call(PRIMARY_TOKEN), call(PROCESS)])


class ImpersonationTests(unittest.TestCase):
    def setUp(self):
        self.api = Mock()
        self.api.open_thread_token.return_value = THREAD_TOKEN
        self.api.token_context.return_value = (SCOPE, 1010)
        self.api.revert.return_value = True
        native = patch.object(windows, "_api", return_value=self.api)
        watcher = patch.object(windows, "watcher_scope", return_value=SCOPE)
        native.start()
        watcher.start()
        self.addCleanup(native.stop)
        self.addCleanup(watcher.stop)

    def test_true_thread_identity_required_and_all_handles_closed(self):
        with windows.impersonate_origin(WORKER_TOKEN) as scope:
            self.assertEqual(scope, SCOPE)
            self.api.revert.assert_not_called()
        self.assertEqual(self.api.mock_calls, [
            call.disable_inheritance(WORKER_TOKEN), call.token_context(WORKER_TOKEN, impersonation=True),
            call.impersonate(WORKER_TOKEN), call.open_thread_token(),
            call.token_context(THREAD_TOKEN, impersonation=True), call.close(THREAD_TOKEN),
            call.revert(), call.close(WORKER_TOKEN),
        ])

    def test_impersonation_failure_prevents_execution_in_ambient_context(self):
        self.api.impersonate.side_effect = PermissionError()
        with self.assertRaisesRegex(windows.OriginUnavailable, "ORIGIN_IMPERSONATION_UNAVAILABLE"):
            with windows.impersonate_origin(WORKER_TOKEN):
                self.fail("Worker must not run using ambient authorization")
        self.api.revert.assert_not_called()
        self.api.close.assert_called_once_with(WORKER_TOKEN)

    def test_different_thread_token_fails_closed_and_reverts(self):
        self.api.token_context.side_effect = [(SCOPE, 1010), (SCOPE, 1011)]
        with self.assertRaisesRegex(windows.OriginUnavailable, "ORIGIN_IMPERSONATION_UNAVAILABLE"):
            with windows.impersonate_origin(WORKER_TOKEN):
                self.fail("Unexpected thread token must prevent file access")
        self.api.revert.assert_called_once()
        self.assertEqual(self.api.close.call_args_list, [call(THREAD_TOKEN), call(WORKER_TOKEN)])


class VolumeTests(unittest.TestCase):
    def setUp(self):
        self.api = Mock()
        self.api.drive_type.return_value = 3
        self.api.device_for_drive.return_value = r"\Device\HarddiskVolume2"
        override = patch.object(windows, "_api", return_value=self.api)
        override.start()
        self.addCleanup(override.stop)
        self.path = PureWindowsPath(r"C:\fixture\synthetic.txt")

    def test_same_device_and_path_are_accepted_on_same_open_handle(self):
        drive = windows.verify_drive(self.path)
        self.api.file_device_path.return_value = r"\Device\HarddiskVolume2\fixture\synthetic.txt"
        stream = object()
        windows.verify_file_volume(stream, drive)
        self.api.file_device_path.assert_called_once_with(stream)

    def test_volume_change_and_same_volume_path_change_fail_closed(self):
        drive = windows.verify_drive(self.path)
        for path, mapping in ((r"\Device\HarddiskVolume3\fixture\synthetic.txt", r"\Device\HarddiskVolume2"),
                              (r"\Device\HarddiskVolume2\fixture\different.txt", r"\Device\HarddiskVolume2"),
                              (r"\Device\HarddiskVolume2\fixture\synthetic.txt", r"\Device\HarddiskVolume3")):
            with self.subTest(path=path, mapping=mapping):
                self.api.file_device_path.return_value = path
                self.api.device_for_drive.return_value = mapping
                with self.assertRaisesRegex(windows.PathContextUnavailable, "UNSUPPORTED_SOURCE_ALIAS"):
                    windows.verify_file_volume(object(), drive)

    def test_remote_and_substituted_drives_are_rejected(self):
        self.api.drive_type.return_value = 4
        with self.assertRaisesRegex(windows.PathContextUnavailable, "NON_LOCAL_SOURCE_VOLUME"):
            windows.verify_drive(self.path)
        self.api.device_for_drive.assert_not_called()
        self.api.drive_type.return_value = 3
        self.api.device_for_drive.return_value = r"\??\C:\fixture"
        with self.assertRaisesRegex(windows.PathContextUnavailable, "UNSUPPORTED_SOURCE_ALIAS"):
            windows.verify_drive(self.path)


if __name__ == "__main__":
    unittest.main()
