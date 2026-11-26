"""Managed entry, private journal ACL and cleanup ordering regressions."""

import ctypes
from ctypes import wintypes as w
from contextlib import ExitStack, nullcontext
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import curl_desktop as desktop
import curl_managed as managed


class EntryTests(unittest.TestCase):
    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        self.scope = stack.enter_context(patch.object(managed, "watcher_scope")).return_value
        factory = stack.enter_context(patch.object(managed, "ManagedInstance", return_value=MagicMock()))
        self.instance = factory.return_value.__enter__.return_value
        self.instance.admitted = True
        self.instance.finish.return_value = "complete"
        self.desktop = stack.enter_context(patch.object(managed, "session_end_notifications",
                                                        return_value=nullcontext()))
        self.private = stack.enter_context(patch.object(managed, "private_journal_directory"))
        self.load = stack.enter_context(patch.object(managed, "_load_watcher"))
        self.watch = self.load.return_value
        self.watch.return_value = {"pending_resumes": 0, "worker_cleanup_confirmed": True,
                                   "report_drained": True, "runtime_failed": False}

    def test_no_enrollment_or_journals_for_duplicate_or_maintenance(self):
        self.instance.admitted = False
        self.assertEqual(managed.run(), 0)
        self.private.assert_not_called()
        self.watch.assert_not_called()
        self.instance.finish.assert_not_called()

    def test_scoped_watcher_receipt_precedes_exit(self):
        self.assertEqual(managed.run(), 0)
        managed.ManagedInstance.assert_called_once_with(self.scope)
        self.private.assert_called_once_with(self.scope)
        self.desktop.assert_called_once_with(self.instance.stop)
        self.watch.assert_called_once_with(managed.CONFIG, self.scope, self.instance.stop)
        self.instance.finish.assert_called_once_with(self.watch.return_value)

    def test_insecure_logs_prevent_monitor_start(self):
        self.private.side_effect = PermissionError()
        with self.assertRaises(PermissionError):
            managed.run()
        self.watch.assert_not_called()
        self.assertTrue(self.instance.finish.call_args.args[0]["runtime_failed"])

    def test_exception_while_scanning_never_supplies_clean_outcome(self):
        self.watch.side_effect = RuntimeError()
        with self.assertRaises(RuntimeError):
            managed.run()
        self.instance.finish.assert_not_called()

    def test_runtime_failure_and_incomplete_cleanup_have_different_exit_codes(self):
        self.watch.return_value["runtime_failed"] = True
        self.assertEqual(managed.run(), 1)
        self.instance.finish.return_value = "incomplete"
        self.assertEqual(managed.run(), 2)


class PrivateJournalTests(unittest.TestCase):
    def test_inherited_log_directory_is_overridden_before_import(self):
        directory = Path("private")
        writer = SimpleNamespace(LOG_FILE=directory / "dlp_events.log",
                                 CURL_DELIVERY_FILE=directory / "curl_delivery.log")
        with (patch.dict(os.environ, DLP_LOG_DIR="shared"),
              patch.dict(sys.modules, log_writer=writer, curl_agent=Mock())):
            managed._load_watcher(directory)
            self.assertEqual(os.environ["DLP_LOG_DIR"], str(directory))
            writer.CURL_DELIVERY_FILE = Path("shared") / "curl_delivery.log"
            with self.assertRaises(RuntimeError):
                managed._load_watcher(directory)

    def test_reparse_point_and_linked_files_refused(self):
        path = Mock()
        info = path.lstat.return_value
        info.st_file_attributes = stat.FILE_ATTRIBUTE_REPARSE_POINT
        with self.assertRaises(OSError):
            desktop._check_local_path(path, directory=True)
        info.st_file_attributes, info.st_mode, info.st_nlink = 0, stat.S_IFREG, 2
        with self.assertRaises(OSError):
            desktop._check_local_path(path, directory=False)

    @unittest.skipUnless(sys.platform == "win32", "Windows DACL conversion")
    def test_native_private_and_leaking_dacls_in_memory(self):
        # Construct actual security descriptors in memory. No ACLs on HOST are changed.
        api = ctypes.WinDLL("advapi32", use_last_error=True)
        bind = desktop._bind
        convert = bind(api, "ConvertStringSecurityDescriptorToSecurityDescriptorW", w.BOOL,
                       w.LPCWSTR, w.DWORD, ctypes.POINTER(w.LPVOID), w.LPVOID)
        owner = bind(api, "GetSecurityDescriptorOwner", w.BOOL, w.LPVOID,
                     ctypes.POINTER(w.LPVOID), ctypes.POINTER(w.BOOL))
        dacl = bind(api, "GetSecurityDescriptorDacl", w.BOOL, w.LPVOID, ctypes.POINTER(w.BOOL),
                    ctypes.POINTER(w.LPVOID), ctypes.POINTER(w.BOOL))
        free = bind(ctypes.WinDLL("kernel32"), "LocalFree", w.HANDLE, w.HANDLE)
        sid = bytes.fromhex("010200000000000515000000d2040000")
        for owner_sid, aces, directory, valid in [
            ("S-1-5-21-1234", "(A;OICI;FA;;;S-1-5-21-1234)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", True, True),
            ("S-1-5-21-1234", "(A;ID;FA;;;S-1-5-21-1234)", False, True),
            ("S-1-5-21-1234", "(A;OICI;FA;;;S-1-5-21-1234)(A;OICI;FR;;;BU)", True, False),
            ("S-1-5-21-1234", "(A;;FA;;;S-1-5-21-1234)", True, False),
            ("WD", "(A;OICI;FA;;;S-1-5-21-1234)", True, False),
        ]:
            with self.subTest(owner=owner_sid, aces=aces):
                descriptor = w.LPVOID()
                self.assertTrue(convert("O:" + owner_sid + "D:P" + aces, 1, ctypes.byref(descriptor), None))

                def read_descriptor(_name, _kind, _flags, owner_out, _group, acl_out, _sacl, sd_out):
                    flag, present = w.BOOL(), w.BOOL()
                    self.assertTrue(owner(descriptor, owner_out, ctypes.byref(flag)))
                    self.assertTrue(dacl(descriptor, ctypes.byref(present), acl_out, ctypes.byref(flag)))
                    ctypes.cast(sd_out, ctypes.POINTER(w.LPVOID))[0] = descriptor
                    return 0

                def substitute(dll, name, *args):
                    return read_descriptor if name == "GetNamedSecurityInfoW" else bind(dll, name, *args)

                with patch.object(desktop, "_bind", side_effect=substitute):
                    with (nullcontext() if valid else self.assertRaises(OSError)):
                        desktop._validate_acl(api, free, "in-memory", sid, directory=directory)


if __name__ == "__main__":
    unittest.main()
