"""Synthetic tests for USB discovery, watcher lifecycle, and the command modes."""

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, call, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import usb_watcher

if sys.platform == "win32":
    import _winapi
    import _windows_dry_run
    import content_inspection


class UsbLifecycleTests(unittest.TestCase):
    def test_insert_stay_remove_and_reinsert_under_different_letters(self):
        system = {"Number": 0, "BusType": "NVMe", "Path": "system",
                  "IsBoot": True, "IsSystem": True}
        usb_boot = {**system, "Number": 1, "BusType": "USB", "Path": "usb-boot"}
        data = {"Number": 3, "BusType": "USB", "Path": "usb-data",
                "IsBoot": False, "IsSystem": False}
        unmounted = {**data, "Number": 4, "Path": "usb-unmounted"}
        disks = [system, usb_boot, unmounted]
        partitions = [{"DiskNumber": 0, "DriveLetter": "C"},
                      {"DiskNumber": 1, "DriveLetter": "D"},
                      {"DiskNumber": 4, "DriveLetter": "\x00"}]

        def scan(letters=(), number=3):
            current_disks = disks + ([{**data, "Number": number}] if letters else [])
            current_partitions = partitions + [
                {"DiskNumber": number, "DriveLetter": letter} for letter in letters
            ]
            return usb_watcher.usb_disks_from_storage(current_disks, current_partitions)

        previous = {}
        first = usb_watcher.UsbDisk(3, ("F", "G"))
        reinserted = usb_watcher.UsbDisk(5, ("J",))
        for current, expected in (
            (scan(), []),
            (scan(("G", "f", "F")), [("inserted", first)]),
            (scan(("F", "G")), []),
            (scan(), [("removed", first)]),
            (scan(("J",), number=5), [("inserted", reinserted)]),
            (scan(("J",), number=5), []),
        ):
            self.assertEqual(usb_watcher.usb_changes(previous, current), expected)
            previous = current
        self.assertEqual(scan(), {})


class UsbFailureRegressionTests(unittest.TestCase):
    def test_factory_failure_does_not_keep_a_partial_batch(self):
        retained, obsolete, first_attempt, replacement, additional = [Mock() for _ in range(5)]
        previous = {"usb-a": usb_watcher.UsbDisk(3, ("F", "H"))}
        current = {"usb-a": usb_watcher.UsbDisk(3, ("H",)),
                   "usb-b": usb_watcher.UsbDisk(4, ("F", "G"))}
        provider = Mock(side_effect=[previous, current, current])
        factory = Mock(side_effect=[
            obsolete, retained, first_attempt, RuntimeError("factory failed"), replacement, additional,
        ])
        manager = usb_watcher.UsbWatcherManager(provider, factory)
        manager.tick()

        with self.assertRaisesRegex(RuntimeError, "factory failed"):
            manager.tick()
        self.assertEqual(manager._watchers, {("usb-a", "H"): retained})
        retained.poll.assert_called_once_with()
        first_attempt.poll.assert_not_called()

        self.assertEqual(manager.tick(), [
            ("removed", "usb-a", "F"), ("inserted", "usb-b", "F"), ("inserted", "usb-b", "G"),
        ])
        self.assertEqual(factory.call_args_list, [
            call("usb-a", "F"), call("usb-a", "H"), call("usb-b", "F"), call("usb-b", "G"),
            call("usb-b", "F"), call("usb-b", "G"),
        ])
        obsolete.poll.assert_called_once_with()
        first_attempt.poll.assert_not_called()
        replacement.poll.assert_called_once_with()
        additional.poll.assert_called_once_with()
        self.assertEqual(retained.poll.call_count, 2)

    def test_poll_failure_keeps_insertion_pending_until_successful_tick(self):
        watcher = Mock()
        watcher.poll.side_effect = [RuntimeError("poll failed"), None, None]
        factory = Mock(return_value=watcher)
        snapshot = {"usb-a": usb_watcher.UsbDisk(3, ("F",))}
        manager = usb_watcher.UsbWatcherManager(Mock(return_value=snapshot), factory)

        with self.assertRaisesRegex(RuntimeError, "poll failed"):
            manager.tick()
        self.assertEqual(manager.tick(), [("inserted", "usb-a", "F")])
        self.assertEqual(manager.tick(), [])
        factory.assert_called_once_with("usb-a", "F")

    def test_duplicate_physical_paths_are_rejected_case_insensitively(self):
        disk = {"Number": 3, "Path": "USB-DISK", "BusType": "USB",
                "IsBoot": False, "IsSystem": False}
        disks = [disk, {**disk, "Number": 4, "Path": "usb-disk"}]
        partitions = [{"DiskNumber": 3, "DriveLetter": "F"}, {"DiskNumber": 4, "DriveLetter": "G"}]
        with self.assertRaisesRegex(ValueError, "Duplicate physical disk path"):
            usb_watcher.usb_disks_from_storage(disks, partitions)

    def test_poll_error_is_raised_after_healthy_volume_has_polled(self):
        failing, healthy = Mock(), Mock()
        failing.poll.side_effect = OSError("first volume failed")
        snapshot = {"usb-a": usb_watcher.UsbDisk(3, ("G", "F"))}
        manager = usb_watcher.UsbWatcherManager(
            Mock(return_value=snapshot), Mock(side_effect=[failing, healthy]))

        with self.assertRaisesRegex(OSError, "first volume failed"):
            manager.tick()
        failing.poll.assert_called_once_with()
        healthy.poll.assert_called_once_with()

        healthy.poll.side_effect = ValueError("second volume failed")
        with self.assertRaisesRegex(RuntimeError, "first volume failed.*second volume failed"):
            manager.tick()
        self.assertEqual(failing.poll.call_count, 2)
        self.assertEqual(healthy.poll.call_count, 2)


class UsbCommandTests(unittest.TestCase):
    def test_list_uses_storage_query_and_prints_disk_letters(self):
        storage = {
            "disks": [{"Number": 8, "BusType": "USB", "Path": "usb-storage",
                       "IsBoot": False, "IsSystem": False}],
            "partitions": [{"DiskNumber": 8, "DriveLetter": "K"}],
        }
        output = io.StringIO()
        with patch.object(usb_watcher.sys, "platform", "win32"), \
                patch.object(usb_watcher.subprocess, "run") as run, redirect_stdout(output):
            run.return_value.stdout = json.dumps(storage)
            usb_watcher.main(["--list-usb"])
        self.assertEqual(output.getvalue().strip(), "Disk 8 (USB): K:")
        self.assertIn("Get-Disk", run.call_args.args[0][-1])
        self.assertIn("Get-Partition", run.call_args.args[0][-1])

    def test_empty_storage_snapshot_exits_normally_with_message(self):
        output = io.StringIO()
        with patch.object(usb_watcher.sys, "platform", "win32"), \
                patch.object(usb_watcher.subprocess, "run") as run, redirect_stdout(output):
            run.return_value.stdout = '{"disks":[],"partitions":[]}'
            usb_watcher.main(["--list-usb"])
        self.assertEqual(output.getvalue().strip(), "No USB data disks with assigned drive letters found.")

    def test_storage_failure_is_distinct_from_empty_result(self):
        error = subprocess.CalledProcessError(1, "powershell.exe", stderr="Storage access denied")
        stderr = io.StringIO()
        with patch.object(usb_watcher.sys, "platform", "win32"), \
                patch.object(usb_watcher.subprocess, "run", side_effect=error), redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as raised:
                usb_watcher.main(["--list-usb"])
        self.assertEqual(raised.exception.code, 1)
        self.assertIn("Storage access denied", stderr.getvalue())

    def test_demo_modes_keep_their_original_dispatch(self):
        with patch.object(usb_watcher, "demo") as offline, \
                patch.object(usb_watcher, "server_demo") as configured:
            usb_watcher.main(["--demo"])
            offline.assert_called_once_with()
            configured.assert_not_called()
            usb_watcher.main(["--demo", "--config", "synthetic.ini"])
            configured.assert_called_once_with("synthetic.ini")
            offline.assert_called_once_with()


@unittest.skipUnless(sys.platform == "win32", "Windows dry-run handle access required")
class UsbDryRunDemoTests(unittest.TestCase):
    def test_dry_run_demo_uses_real_inspection_without_usb_or_server(self):
        output = io.StringIO()
        retained = []
        original_poll = usb_watcher.DryRunFolderWatcher.poll

        def retain_watcher(watcher):
            retained.append(watcher)
            return original_poll(watcher)

        with tempfile.TemporaryDirectory() as directory, \
                patch.object(usb_watcher.tempfile, "gettempdir", return_value=directory), \
                patch.object(usb_watcher.DryRunFolderWatcher, "poll", autospec=True,
                             side_effect=retain_watcher), \
                patch.object(usb_watcher, "inspect_file", wraps=usb_watcher.inspect_file) as inspect, \
                patch.object(usb_watcher, "FolderWatcher") as folder, \
                patch.object(usb_watcher, "scan_windows_usb") as scan, \
                patch("policy_client.PolicyClient") as client, redirect_stdout(output):
            usb_watcher.main(["--dry-run-demo"])
            self.assertEqual(len(retained), 4)
            self.assertEqual(list(Path(directory).iterdir()), [])
            with self.assertRaisesRegex(ValueError, "fixture root is closed"):
                retained[0].poll()
        self.assertEqual(inspect.call_count, 3)
        folder.assert_not_called()
        scan.assert_not_called()
        client.assert_not_called()
        text = output.getvalue()
        self.assertIn("USB DRY-RUN / SIMULATION", text)
        self.assertRegex(text, r"(?m)^clean\.txt\s+ALLOW\s+ALLOW\s+11$")
        self.assertRegex(text, r"(?m)^monitor\.txt\s+LOG\s+LOGGED\s+22$")
        self.assertRegex(text, r"(?m)^sensitive\.txt\s+BLOCK\s+WOULD_BLOCK\s+11$")
        self.assertIn("All 3 files unchanged. No duplicate events after 2 extra polls.", text)

    def test_dry_run_demo_rejects_external_directories_and_incompatible_options(self):
        with patch.object(usb_watcher, "dry_run_demo") as demo:
            for options in (
                ["synthetic-folder"], ["--directory", "synthetic-folder"], ["--config", "synthetic.ini"],
                ["--demo"], ["--list-usb"], ["--observe-usb"], ["--iterations", "2"],
            ):
                with self.subTest(options=options), redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as raised:
                        usb_watcher.main(["--dry-run-demo", *options])
                    self.assertEqual(raised.exception.code, 2)
        demo.assert_not_called()

    def test_dry_run_demo_exits_nonzero_if_results_are_missing(self):
        with patch.object(usb_watcher.DryRunFolderWatcher, "poll", return_value=[]):
            self.assert_demo_failure("Unexpected inspection results")

    def test_dry_run_demo_exits_nonzero_for_duplicate_events(self):
        original_poll = usb_watcher.DryRunFolderWatcher.poll
        reported = []

        def repeated_poll(watcher):
            if reported:
                return reported
            reported.extend(original_poll(watcher))
            return reported

        with patch.object(usb_watcher.DryRunFolderWatcher, "poll", autospec=True, side_effect=repeated_poll):
            self.assert_demo_failure("Extra polls produced unexpected events")

    def test_dry_run_demo_exits_nonzero_if_fixture_changes(self):
        original_poll = usb_watcher.DryRunFolderWatcher.poll
        polls = 0

        def poll_with_fixture_change(watcher):
            nonlocal polls
            polls += 1
            events = original_poll(watcher)
            if polls == 4:
                with watcher._fixture.scan() as scan:
                    handle = _windows_dry_run._open_relative(
                        scan._handle, "clean.txt", _windows_dry_run._FILE_WRITE_DATA,
                        _windows_dry_run._SHARE_ALL, directory=False)
                    with _windows_dry_run._binary_stream(handle, "wb") as stream:
                        stream.write(b"changed during synthetic test")
            return events

        with patch.object(usb_watcher.DryRunFolderWatcher, "poll", autospec=True,
                          side_effect=poll_with_fixture_change):
            self.assert_demo_failure("Synthetic file changed: clean.txt")

    def test_demo_cleanup_targets_only_its_owned_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            with _windows_dry_run.temporary_fixture(parent) as fixture:
                clean_root = fixture.path
                fixture.write_new("created.txt", b"test fixture")
            self.assertFalse(clean_root.exists())

            with _windows_dry_run.temporary_fixture(parent) as fixture:
                fixture.write_new("created.txt", b"test fixture")
                unrelated = fixture.path / "unrelated.txt"
                unrelated.write_bytes(b"preserve")
                with self.assertRaises(FileExistsError):
                    fixture.write_new(unrelated.name, b"replacement")

                replacement = parent / "replacement"
                replacement.mkdir()
                with patch.object(_windows_dry_run.DirectoryScan, "names") as names:
                    with self.assertRaisesRegex(ValueError, "fixture directory was replaced"):
                        usb_watcher.DryRunFolderWatcher(
                            replacement, [], _expected_identity=fixture.identity)
                names.assert_not_called()
            self.assertEqual(unrelated.read_bytes(), b"preserve")
            self.assertFalse((unrelated.parent / "created.txt").exists())

    def test_demo_preserves_preexisting_directory_on_name_collision(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            collision = parent / "dlp-usb-dry-run-collision"
            collision.mkdir()
            unrelated = collision / "unrelated.txt"
            unrelated.write_bytes(b"preserve")
            with patch.object(_windows_dry_run.uuid, "uuid4", return_value=Mock(hex="collision")):
                with self.assertRaises(FileExistsError):
                    with _windows_dry_run.temporary_fixture(parent):
                        self.fail("expected exclusive directory creation to fail")
            self.assertEqual(unrelated.read_bytes(), b"preserve")

    def test_demo_releases_handles_while_setup_or_poll_exception_is_retained(self):
        for step in ("_snapshot", "_poll_scan"):
            failure = RuntimeError(f"synthetic failure in {step}")
            with self.subTest(step=step), tempfile.TemporaryDirectory() as directory, \
                    patch.object(usb_watcher.tempfile, "gettempdir", return_value=directory), \
                    patch.object(usb_watcher.DryRunFolderWatcher, step, autospec=True,
                                 side_effect=failure) as fail, redirect_stdout(io.StringIO()):
                try:
                    usb_watcher.dry_run_demo()
                except RuntimeError as caught:
                    self.assertIs(caught, failure)
                    self.assertIsNotNone(caught.__traceback__)
                    self.assertEqual(list(Path(directory).iterdir()), [])
                    watcher, scan = fail.call_args.args
                    self.assertFalse(watcher._fixture._release.alive)
                    with self.assertRaisesRegex(ValueError, "directory scan is closed"):
                        next(scan.names())
                else:
                    self.fail(f"Expected failure in {step}")

    def test_demo_removes_partially_created_fixture_if_writer_cannot_open(self):
        open_relative = _windows_dry_run._open_relative

        def fail_writer(parent, name, access, share, **kwargs):
            if name == "monitor.txt" and access & _windows_dry_run._FILE_WRITE_DATA:
                raise PermissionError("synthetic writer open failed")
            return open_relative(parent, name, access, share, **kwargs)

        with patch.object(_windows_dry_run, "_open_relative", side_effect=fail_writer):
            self.assert_demo_failure("synthetic writer open failed")

    def assert_demo_failure(self, message):
        stdout, stderr = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(usb_watcher.tempfile, "gettempdir", return_value=directory), \
                redirect_stdout(stdout), redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as raised:
                usb_watcher.main(["--dry-run-demo"])
            self.assertEqual(list(Path(directory).iterdir()), [])
        self.assertEqual(raised.exception.code, 1)
        self.assertIn("USB DRY-RUN / SIMULATION", stdout.getvalue())
        self.assertIn(message, stderr.getvalue())
        self.assertNotIn("PASS:", stdout.getvalue())


class UsbObserverTests(unittest.TestCase):
    device = r"\synthetic\USBSTOR\serial-test"

    def setUp(self):
        scanner = patch.object(usb_watcher, "scan_windows_usb")
        sleeper = patch.object(usb_watcher.time, "sleep")
        self.scan = scanner.start()
        self.sleep = sleeper.start()
        self.addCleanup(scanner.stop)
        self.addCleanup(sleeper.stop)

    def snapshot(self, *letters):
        return {self.device: usb_watcher.UsbDisk(3, letters)}

    def observe(self, *snapshots):
        self.scan.side_effect = snapshots
        output = io.StringIO()
        with redirect_stdout(output):
            usb_watcher.main(["--observe-usb", "--iterations", str(len(snapshots)), "--interval", "0"])
        return output.getvalue().splitlines()

    def test_initial_scan_prints_letter_without_physical_identity(self):
        self.assertEqual(self.observe(self.snapshot("F")), ["inserted F:"])

    def test_stable_snapshots_emit_no_duplicate_events(self):
        snapshot = self.snapshot("F")
        self.assertEqual(self.observe(snapshot, snapshot, snapshot), ["inserted F:"])

    def test_removal_and_reinsertion(self):
        self.assertEqual(self.observe(self.snapshot("F"), {}, self.snapshot("F")),
                         ["inserted F:", "removed F:", "inserted F:"])

    def test_drive_letter_reassignment_on_same_device(self):
        self.assertEqual(self.observe(self.snapshot("F"), self.snapshot("J")),
                         ["inserted F:", "removed F:", "inserted J:"])

    def test_multiple_volumes_have_separate_events(self):
        self.assertEqual(self.observe(self.snapshot("G", "F"), self.snapshot("G")),
                         ["inserted F:", "inserted G:", "removed F:"])

    def test_empty_snapshots_exit_normally(self):
        self.assertEqual(self.observe({}, {}), [])
        self.assertEqual(self.scan.call_count, 2)

    def test_storage_failure_exits_without_false_removal_or_identifier(self):
        self.scan.side_effect = [self.snapshot("F"), RuntimeError(f"Access denied: {self.device}")]
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            usb_watcher.main(["--observe-usb", "--iterations", "3", "--interval", "1"])
        self.assertEqual(raised.exception.code, 1)
        self.assertEqual(stdout.getvalue().splitlines(), ["inserted F:"])
        self.assertIn("could not read or validate Windows storage metadata", stderr.getvalue())
        self.assertNotIn(self.device, stderr.getvalue())
        self.assertEqual(self.scan.call_count, 2)
        self.sleep.assert_called_once_with(1)

    def test_invalid_observation_arguments_are_rejected_before_scanning(self):
        for argv in (
            ["--observe-usb", "--iterations", "0"],
            ["--observe-usb", "--iterations", "-1"],
            ["--observe-usb", "--iterations", "61"],
            ["--observe-usb", "--iterations", "2.5"],
            ["--observe-usb", "--interval", "-1"],
            ["--observe-usb", "--interval", "61"],
            ["--observe-usb", "--interval", "nan"],
            ["--observe-usb", "--interval", "inf"],
            ["--observe-usb", "--list-usb"],
            ["--observe-usb", "--demo"],
            ["--observe-usb", "--config", "synthetic.ini"],
            ["--demo", "--interval", "2"],
            ["--list-usb", "--iterations", "3"],
        ):
            with self.subTest(argv=argv), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    usb_watcher.main(argv)
                self.assertEqual(raised.exception.code, 2)
        self.scan.assert_not_called()
        self.sleep.assert_not_called()

    def test_iteration_limit_and_sleep_only_between_scans(self):
        self.scan.return_value = {}
        usb_watcher.main(["--observe-usb"])
        self.assertEqual(self.scan.call_count, 3)
        self.assertEqual(self.sleep.call_args_list, [call(2), call(2)])

        self.scan.reset_mock()
        self.sleep.reset_mock()
        usb_watcher.main(["--observe-usb", "--iterations", "60", "--interval", "0"])
        self.assertEqual(self.scan.call_count, 60)
        self.sleep.assert_not_called()

    def test_interruption_stops_cleanly_before_next_scan(self):
        self.scan.return_value = self.snapshot("F")
        self.sleep.side_effect = KeyboardInterrupt
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            usb_watcher.main(["--observe-usb"])
        self.assertEqual(raised.exception.code, 130)
        self.assertEqual(stdout.getvalue().splitlines(), ["inserted F:"])
        self.assertEqual(stderr.getvalue(), "USB observation interrupted.\n")
        self.scan.assert_called_once_with()

    def test_observer_watcher_avoids_filesystem_access(self):
        with patch.object(usb_watcher, "Path") as path, patch("builtins.open") as open_file, \
                patch("os.open") as os_open, patch("os.scandir") as scandir, \
                patch("os.listdir") as listdir:
            self.assertEqual(self.observe(self.snapshot("F"), self.snapshot("F"), {}),
                             ["inserted F:", "removed F:"])
        for filesystem_call in (path, open_file, os_open, scandir, listdir):
            filesystem_call.assert_not_called()

    def test_observer_does_not_use_folder_watcher_or_server(self):
        with patch.object(usb_watcher, "FolderWatcher") as folder, \
                patch.object(usb_watcher, "inspect_file") as inspect, \
                patch("policy_client.PolicyClient") as client:
            self.assertEqual(self.observe(self.snapshot("F")), ["inserted F:"])
        folder.assert_not_called()
        inspect.assert_not_called()
        client.assert_not_called()


@unittest.skipUnless(sys.platform == "win32", "Windows dry-run handle access required")
class UsbDryRunTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name) / "watched"
        self.root.mkdir()
        self.policies = [
            {"policy_id": pid, "action": action, "exit_points": ["USB"],
             "content_rules": [{"id": rid, "rule_name": marker, "pattern": marker,
                                "rule_type": "REGEX", "severity": "HIGH", "category": "INTERNAL_DOC"}]}
            for pid, rid, marker, action in (
                (11, 111, "ALPHA", "BLOCK"), (22, 222, "BETA", "REPORT_ONLY"),
            )
        ]
        self.watcher = usb_watcher.DryRunFolderWatcher(self.root, self.policies)
        self.addCleanup(self.watcher.close)

    def write(self, name, content):
        path = self.root / name
        path.write_text(content, encoding="utf-8")
        return path

    def test_new_files_keep_independent_decisions_and_policy_evidence(self):
        self.watcher = usb_watcher.DryRunFolderWatcher(self.root, self.policies[::-1])
        self.addCleanup(self.watcher.close)
        self.write("clean.txt", "ordinary")
        self.write("mixed.txt", "ALPHA BETA")
        self.write("monitor.txt", "BETA")
        self.assertEqual(self.watcher.poll(), [])
        events = self.watcher.poll()
        self.assertEqual([(e["file_name"], e["verdict"], e["action_taken"]) for e in events],
                         [("clean.txt", "ALLOW", "ALLOW"), ("mixed.txt", "BLOCK", "WOULD_BLOCK"),
                          ("monitor.txt", "LOG", "LOGGED")])
        self.assertEqual([(e["policy_id"], e["matched_rule_ids"], e["confidence_level"])
                          for e in events[1:]], [(11, [111], "MEDIUM"), (22, [222], "MEDIUM")])
        self.assertEqual(self.watcher.poll(), [])

    def test_partial_writes_need_two_matching_snapshots(self):
        self.write("copy.txt", "AL")
        self.assertEqual(self.watcher.poll(), [])
        self.write("copy.txt", "ALPHA")
        self.assertEqual(self.watcher.poll(), [])
        self.assertEqual([e["action_taken"] for e in self.watcher.poll()], ["WOULD_BLOCK"])

    def test_startup_baseline_ignores_existing_file_but_detects_same_size_overwrite(self):
        path = self.write("existing.txt", "BETA ")
        original = path.stat()
        watcher = usb_watcher.DryRunFolderWatcher(self.root, self.policies)
        self.addCleanup(watcher.close)
        self.assertEqual(watcher.poll(), [])
        self.write("existing.txt", "ALPHA")
        os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns + 2_000_000_000))
        self.assertEqual(watcher.poll(), [])
        self.assertEqual([e["action_taken"] for e in watcher.poll()], ["WOULD_BLOCK"])
        self.assertEqual(watcher.poll(), [])

    def test_delete_and_recreate_emits_a_new_event(self):
        path = self.write("reused.txt", "ALPHA")
        self.watcher.poll()
        self.assertEqual(len(self.watcher.poll()), 1)
        path.unlink()
        self.assertEqual(self.watcher.poll(), [])
        self.write("reused.txt", "ALPHA")
        self.assertEqual(self.watcher.poll(), [])
        self.assertEqual([e["action_taken"] for e in self.watcher.poll()], ["WOULD_BLOCK"])

    def test_replacement_at_same_path_is_detected(self):
        path = self.write("replaced.txt", "ALPHA")
        self.watcher.poll()
        self.assertEqual(len(self.watcher.poll()), 1)
        original = path.stat()
        replacement = self.write("replacement.tmp", "ALPHA")
        os.utime(replacement, ns=(original.st_atime_ns, original.st_mtime_ns))
        replacement.replace(path)
        self.assertEqual(self.watcher.poll(), [])
        self.assertEqual([e["action_taken"] for e in self.watcher.poll()], ["WOULD_BLOCK"])

    def test_file_changed_during_inspection_is_retried_when_stable(self):
        path = self.write("changing.txt", "ALPHA")
        self.watcher.poll()
        inspect = usb_watcher.inspect_file

        def change_after_inspection(file_path, *args, **kwargs):
            result = inspect(file_path, *args, **kwargs)
            self.write(path.name, "BETA")
            return result

        with patch.object(usb_watcher, "inspect_file", side_effect=change_after_inspection):
            self.assertEqual(self.watcher.poll(), [])
        self.assertEqual(self.watcher.poll(), [])
        events = self.watcher.poll()
        self.assertEqual([(e["action_taken"], e["policy_id"]) for e in events], [("LOGGED", 22)])

    def test_preinspection_metadata_change_defers_the_read(self):
        path = self.write("before-read.txt", "ALPHA")
        self.watcher.poll()
        version = self.watcher._previous[path]
        changed = (*version[:2], version[2] + 1, *version[3:])
        with patch.object(_windows_dry_run.DirectoryScan, "version", side_effect=[version, changed]), \
                patch.object(usb_watcher, "inspect_file") as inspect:
            self.assertEqual(self.watcher.poll(), [])
        inspect.assert_not_called()

    def test_disappearance_during_inspection_does_not_stop_other_files(self):
        disappearing = self.write("a-disappears.txt", "ALPHA")
        self.write("b-clean.txt", "ordinary")
        self.watcher.poll()
        inspect = usb_watcher.inspect_file

        def remove_after_inspection(path, *args, **kwargs):
            result = inspect(path, *args, **kwargs)
            if path == disappearing:
                path.unlink()
            return result

        with patch.object(usb_watcher, "inspect_file", side_effect=remove_after_inspection):
            events = self.watcher.poll()
        self.assertEqual([(e["file_name"], e["action_taken"]) for e in events], [("b-clean.txt", "ALLOW")])

    def test_inaccessible_metadata_does_not_stop_other_files_and_recovers(self):
        blocked = self.write("blocked.txt", "ALPHA")
        self.write("clean.txt", "ordinary")
        self.watcher.poll()
        file_version = _windows_dry_run.DirectoryScan.version

        def fail_one(scan, name):
            if name == blocked.name:
                raise PermissionError("temporarily inaccessible")
            return file_version(scan, name)

        with patch.object(_windows_dry_run.DirectoryScan, "version", autospec=True, side_effect=fail_one):
            self.assertEqual([e["file_name"] for e in self.watcher.poll()], ["clean.txt"])
            self.assertEqual(self.watcher.poll(), [])
        self.assertEqual(self.watcher.poll(), [])
        self.assertEqual([e["action_taken"] for e in self.watcher.poll()], ["WOULD_BLOCK"])

    def test_unreadable_verdict_is_preserved_once_and_retried(self):
        self.write("read-error.txt", "BETA")
        self.watcher.poll()
        with patch("content_inspection._read_stream", side_effect=PermissionError("locked")):
            events = self.watcher.poll()
            self.assertEqual([(e["reason"], e["policy_id"], e["action_taken"]) for e in events],
                             [("UNREADABLE", 11, "WOULD_BLOCK")])
            self.assertEqual(self.watcher.poll(), [])
        self.assertEqual([(e["policy_id"], e["action_taken"]) for e in self.watcher.poll()],
                         [(22, "LOGGED")])
        self.assertEqual(self.watcher.poll(), [])

    def test_history_limit_and_failed_scan_preserve_duplicate_suppression(self):
        watcher = usb_watcher.DryRunFolderWatcher(self.root, self.policies, max_files=1)
        self.addCleanup(watcher.close)
        self.write("tracked.txt", "ALPHA")
        watcher.poll()
        self.assertEqual(len(watcher.poll()), 1)
        overflow = self.write("overflow.txt", "BETA")
        self.assertEqual(watcher.poll(), [])
        overflow.unlink()
        with patch.object(watcher, "_snapshot", side_effect=PermissionError("directory unavailable")):
            with self.assertRaisesRegex(PermissionError, "directory unavailable"):
                watcher.poll()
        self.assertEqual(watcher.poll(), [])
        self.assertEqual(watcher.poll(), [])
        self.write("tracked.txt", "unrelated")
        self.assertEqual(watcher.poll(), [])
        self.assertEqual([e["action_taken"] for e in watcher.poll()], ["ALLOW"])

    def test_dry_run_never_invokes_enforcement_usb_discovery_or_server(self):
        path = self.write("protected.txt", "ALPHA")
        before = path.stat()
        with patch.object(usb_watcher, "FolderWatcher") as enforcing_watcher, \
                patch.object(usb_watcher, "scan_windows_usb") as scanner, \
                patch("policy_client.PolicyClient") as client, \
                patch.object(Path, "unlink") as unlink, patch.object(Path, "rename") as rename, \
                patch.object(Path, "replace") as replace, patch.object(Path, "write_bytes") as write_bytes, \
                patch.object(Path, "write_text") as write_text:
            self.watcher.poll()
            self.assertEqual([e["action_taken"] for e in self.watcher.poll()], ["WOULD_BLOCK"])
            for operation in (enforcing_watcher, scanner, client, unlink, rename, replace, write_bytes, write_text):
                operation.assert_not_called()
        self.assertEqual(path.read_bytes(), b"ALPHA")
        after = path.stat()
        self.assertEqual((after.st_ino, after.st_size, after.st_mtime_ns),
                         (before.st_ino, before.st_size, before.st_mtime_ns))

    def test_drive_root_is_rejected_without_reading_it(self):
        with patch.object(_windows_dry_run, "local_fixture_volume") as volume:
            with self.assertRaisesRegex(ValueError, "under the system temporary directory"):
                usb_watcher.DryRunFolderWatcher(self.root.anchor, self.policies)
            volume.assert_not_called()

    def test_fixed_drive_reporting_usb_is_rejected_before_directory_access(self):
        def usb_descriptor(handle, control, query, query_size, response, size, returned, overlapped):
            response[28] = b"\x07"
            returned._obj.value = 32
            return True

        with patch.object(_windows_dry_run, "_device_control", side_effect=usb_descriptor), \
                patch.object(_windows_dry_run, "FixtureRoot") as opened:
            with self.assertRaisesRegex(ValueError, "known non-USB fixture volume"):
                usb_watcher.DryRunFolderWatcher(self.root, self.policies)
        opened.assert_not_called()

    def test_missing_root_raises_instead_of_reporting_an_empty_scan(self):
        original = self.root.with_name("original")
        self.root.rename(original)
        with self.assertRaises(FileNotFoundError):
            self.watcher.poll()
        self.root.mkdir()
        self.write("replacement.txt", "ALPHA")
        with patch.object(_windows_dry_run.DirectoryScan, "names", autospec=True) as names:
            with self.assertRaisesRegex(ValueError, "fixture directory was replaced"):
                self.watcher.poll()
        names.assert_not_called()
        self.root.rename(self.root.with_name("replacement"))
        original.rename(self.root)
        self.assertEqual(self.watcher.poll(), [])

    def test_reparse_points_are_not_inspected_or_used_as_watcher_roots(self):
        child = self.write("reparse.txt", "ALPHA")
        junction = self.root.with_name("junction")
        _winapi.CreateJunction(str(self.root), str(junction))
        for path in (junction, junction / "nested"):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "links or reparse points"):
                usb_watcher.DryRunFolderWatcher(path, self.policies)

        identity = child.stat().st_ino
        original_query = _windows_dry_run._query

        def metadata(handle, info_type, structure):
            info = original_query(handle, info_type, structure)
            if structure is _windows_dry_run._BasicInfo:
                _, file_id = _windows_dry_run._identity(handle)
                if int.from_bytes(file_id, "little") == identity:
                    info.attributes |= stat.FILE_ATTRIBUTE_REPARSE_POINT
            return info

        with patch.object(_windows_dry_run, "_query", side_effect=metadata), \
                patch.object(_windows_dry_run, "_file_version", wraps=_windows_dry_run._file_version) as version, \
                patch.object(usb_watcher, "inspect_file") as inspect:
            self.assertEqual(self.watcher.poll(), [])
            self.assertEqual(self.watcher.poll(), [])
            self.assertGreaterEqual(version.call_count, 2)
            inspect.assert_not_called()

    def test_hard_link_to_sibling_fixture_is_not_inspected(self):
        sibling = self.root.with_name("sibling.txt")
        sibling.write_text("ALPHA", encoding="utf-8")
        os.link(sibling, self.root / "alias.txt")
        with patch.object(usb_watcher, "inspect_file") as inspect:
            self.assertEqual(self.watcher.poll(), [])
            self.assertEqual(self.watcher.poll(), [])
        inspect.assert_not_called()

    def test_file_open_remains_confined_when_child_is_swapped_after_precheck(self):
        candidate = self.write("candidate.txt", "clean")
        staging = self.root / "staging"
        staging.mkdir()
        replacement = staging / "replacement.txt"
        replacement.write_text("ALPHA", encoding="utf-8")
        self.assertEqual(self.watcher.poll(), [])
        inspect = usb_watcher.inspect_file

        def replace_after_precheck(path, *args, **kwargs):
            self.assertEqual(path, candidate)
            candidate.rename(staging / "original.txt")
            replacement.rename(candidate)
            return inspect(path, *args, **kwargs)

        with patch.object(usb_watcher, "inspect_file", side_effect=replace_after_precheck) as inspecting, \
                patch.object(content_inspection, "_read_stream") as read, \
                patch("content_inspection.open", create=True) as path_open:
            self.assertEqual(self.watcher.poll(), [])
        inspecting.assert_called_once()
        read.assert_not_called()
        path_open.assert_not_called()
        self.assertEqual(self.watcher.poll(), [])
        with patch("content_inspection.open", create=True) as path_open:
            events = self.watcher.poll()
        path_open.assert_not_called()
        self.assertEqual([(e["file_name"], e["action_taken"], e["policy_id"], e["file_hash_sha256"])
                          for e in events],
                         [(candidate.name, "WOULD_BLOCK", 11, hashlib.sha256(b"ALPHA").hexdigest())])

    def test_directory_scan_remains_confined_when_root_is_swapped_after_validation(self):
        self.write("candidate.txt", "BETA")
        sibling = self.root.with_name("sibling")
        sibling.mkdir()
        (sibling / "synthetic-target.txt").write_text("ALPHA", encoding="utf-8")
        parked = self.root.with_name("parked")
        self.assertEqual(self.watcher.poll(), [])
        original_names = _windows_dry_run.DirectoryScan.names

        def replace_root_after_validation(scan):
            self.root.rename(parked)
            sibling.rename(self.root)
            yield from original_names(scan)

        with patch.object(_windows_dry_run.DirectoryScan, "names", autospec=True,
                          side_effect=replace_root_after_validation) as names, \
                patch.object(usb_watcher.os, "scandir") as scandir:
            events = self.watcher.poll()
        names.assert_called_once()
        scandir.assert_not_called()
        self.assertEqual([(e["file_name"], e["action_taken"], e["policy_id"]) for e in events],
                         [("candidate.txt", "LOGGED", 22)])
        with self.assertRaisesRegex(ValueError, "fixture directory was replaced"):
            self.watcher.poll()

    def test_content_and_hash_use_open_handle_after_child_rename(self):
        candidate = self.write("candidate.txt", "BETA")
        parked = self.root / "parked.txt"
        self.assertEqual(self.watcher.poll(), [])
        read_stream = content_inspection._read_stream
        hash_stream = content_inspection._sha256_stream

        def rename_before_read(stream, size):
            candidate.rename(parked)
            candidate.write_text("ALPHA", encoding="utf-8")
            data = read_stream(stream, size)
            self.assertEqual(data, b"BETA")
            return data

        def check_hash_source(stream):
            digest = hash_stream(stream)
            self.assertEqual(digest, hashlib.sha256(b"BETA").hexdigest())
            return digest

        with patch.object(content_inspection, "_read_stream", side_effect=rename_before_read) as read, \
                patch.object(content_inspection, "_sha256_stream", side_effect=check_hash_source) as digest:
            self.assertEqual(self.watcher.poll(), [])
        read.assert_called_once()
        digest.assert_called_once()

    def test_close_is_idempotent_and_active_scan_keeps_its_own_handle(self):
        path = self.write("candidate.txt", "BETA")
        self.write("second.txt", "ALPHA")
        root = self.watcher._fixture
        pin = root._release.peek()[2][0]
        with root.scan() as scan:
            scan_handle = scan._handle
            names = scan.names()
            self.assertIn(next(names), {path.name, "second.txt"})
            self.watcher.close()
            self.watcher.close()
            self.assert_native_handle_closed(pin)
            self.assertIsNotNone(scan.version(path.name))
            with self.assertRaisesRegex(ValueError, "fixture root is closed"):
                self.watcher.poll()
        self.assert_native_handle_closed(scan_handle)
        with self.assertRaisesRegex(ValueError, "directory scan is closed"):
            next(names)
        with self.assertRaisesRegex(ValueError, "directory scan is closed"):
            scan.version(path.name)

    def test_binary_stream_closes_the_native_handle_on_setup_or_body_error(self):
        path = self.write("candidate.txt", "BETA")
        with self.watcher._fixture.scan() as scan:
            for phase in ("open_osfhandle", "fdopen", "body"):
                with self.subTest(phase=phase):
                    handle = _windows_dry_run._open_relative(
                        scan._handle, path.name, _windows_dry_run._FILE_READ_DATA,
                        _windows_dry_run._SHARE_ALL, directory=False)
                    with self.assertRaisesRegex(OSError, "synthetic stream failure"):
                        if phase == "body":
                            with _windows_dry_run._binary_stream(handle) as stream:
                                self.assertEqual(stream.read(), b"BETA")
                                raise OSError("synthetic stream failure")
                        else:
                            module = _windows_dry_run.msvcrt if phase == "open_osfhandle" else os
                            with patch.object(module, phase, side_effect=OSError("synthetic stream failure")):
                                with _windows_dry_run._binary_stream(handle):
                                    self.fail("stream setup should fail")
                    self.assert_native_handle_closed(handle)

    def test_demo_fixture_cannot_open_handles_after_exit(self):
        with _windows_dry_run.temporary_fixture(self.root) as fixture:
            handle = fixture._handle
            fixture.write_new("candidate.txt", b"BETA")
        self.assert_native_handle_closed(handle)
        self.assertEqual(list(self.root.iterdir()), [])
        with self.assertRaisesRegex(ValueError, "demo fixture is closed"):
            fixture.identity
        with self.assertRaisesRegex(ValueError, "demo fixture is closed"):
            fixture.write_new("later.txt", b"no")

    def assert_native_handle_closed(self, handle):
        with self.assertRaises(OSError) as invalid:
            _windows_dry_run._identity(handle)
        self.assertEqual(invalid.exception.winerror, 6)  # ERROR_INVALID_HANDLE


class UsbWatcherManagerTests(unittest.TestCase):
    def setUp(self):
        self.provider = Mock()
        self.factory = Mock(side_effect=lambda device, letter: Mock(name=f"{device}/{letter}"))
        self.manager = usb_watcher.UsbWatcherManager(self.provider, self.factory)

    def tick(self, devices):
        self.provider.return_value = devices
        return self.manager.tick()

    def test_initial_detection_creates_once_and_stable_scan_reuses_watcher(self):
        watcher = Mock()
        self.factory.side_effect = None
        self.factory.return_value = watcher
        self.assertEqual(self.tick({"usb-a": usb_watcher.UsbDisk(3, ("F",))}),
                         [("inserted", "usb-a", "F")])
        self.assertEqual(self.tick({"usb-a": usb_watcher.UsbDisk(8, ("F",))}), [])
        self.factory.assert_called_once_with("usb-a", "F")
        self.assertEqual(watcher.poll.call_count, 2)

    def test_removal_stops_polling_and_reinsertion_creates_new_watcher(self):
        first, second = Mock(), Mock()
        self.factory.side_effect = [first, second]
        self.tick({"usb-a": usb_watcher.UsbDisk(3, ("F",))})
        self.assertEqual(self.tick({}), [("removed", "usb-a", "F")])
        self.assertEqual(self.tick({}), [])
        self.assertEqual(self.tick({"usb-a": usb_watcher.UsbDisk(7, ("J",))}),
                         [("inserted", "usb-a", "J")])
        self.assertEqual(self.factory.call_args_list, [call("usb-a", "F"), call("usb-a", "J")])
        first.poll.assert_called_once_with()
        second.poll.assert_called_once_with()

    def test_drive_letter_reassignment_replaces_watcher_without_unplugging(self):
        first, second = Mock(), Mock()
        self.factory.side_effect = [first, second]
        self.tick({"usb-a": usb_watcher.UsbDisk(3, ("F",))})
        self.assertEqual(self.tick({"usb-a": usb_watcher.UsbDisk(3, ("J",))}),
                         [("removed", "usb-a", "F"), ("inserted", "usb-a", "J")])
        self.assertEqual(self.tick({"usb-a": usb_watcher.UsbDisk(3, ("J",))}), [])
        first.poll.assert_called_once_with()
        self.assertEqual(second.poll.call_count, 2)
        self.assertEqual(self.factory.call_args_list, [call("usb-a", "F"), call("usb-a", "J")])

    def test_multiple_volumes_have_deterministic_events_and_independent_watchers(self):
        f, g, j = Mock(), Mock(), Mock()
        self.factory.side_effect = [f, g, j]
        self.assertEqual(self.tick({"usb-a": usb_watcher.UsbDisk(3, ("G", "F", "f"))}),
                         [("inserted", "usb-a", "F"), ("inserted", "usb-a", "G")])
        self.assertEqual(self.tick({"usb-a": usb_watcher.UsbDisk(3, ("J", "g"))}),
                         [("removed", "usb-a", "F"), ("inserted", "usb-a", "J")])
        self.assertEqual(self.factory.call_args_list,
                         [call("usb-a", "F"), call("usb-a", "G"), call("usb-a", "J")])
        f.poll.assert_called_once_with()
        self.assertEqual(g.poll.call_count, 2)
        j.poll.assert_called_once_with()

    def test_reused_letter_removes_old_watcher_before_creating_replacement(self):
        previous, replacement = Mock(), Mock()
        self.factory.side_effect = [previous]
        self.tick({"usb-a": usb_watcher.UsbDisk(3, ("F",))})

        def replace(device, letter):
            self.assertNotIn(("usb-a", "F"), self.manager._watchers)
            return replacement

        self.factory.side_effect = replace
        self.assertEqual(self.tick({"usb-b": usb_watcher.UsbDisk(3, ("F",))}),
                         [("removed", "usb-a", "F"), ("inserted", "usb-b", "F")])
        self.factory.assert_called_with("usb-b", "F")
        previous.poll.assert_called_once_with()
        replacement.poll.assert_called_once_with()

    def test_scan_failure_preserves_watchers_and_skips_polling(self):
        watcher = Mock()
        self.factory.side_effect = [watcher]
        snapshot = {"usb-a": usb_watcher.UsbDisk(3, ("F",))}
        self.tick(snapshot)
        self.provider.side_effect = RuntimeError("Storage query failed")
        with self.assertRaisesRegex(RuntimeError, "Storage query failed"):
            self.manager.tick()
        watcher.poll.assert_called_once_with()
        self.provider.side_effect = None
        self.assertEqual(self.tick(snapshot), [])
        self.factory.assert_called_once_with("usb-a", "F")
        self.assertEqual(watcher.poll.call_count, 2)

    def test_missing_identity_and_conflicting_volume_owners_do_not_create_watchers(self):
        disk = usb_watcher.UsbDisk(3, ("F",))
        for snapshot, error in (
            ({"disk:3": disk}, "physical device identity"),
            ({"usb-a": disk, "usb-b": usb_watcher.UsbDisk(4, ("F",))}, "multiple owners"),
        ):
            with self.subTest(snapshot=snapshot), self.assertRaisesRegex(ValueError, error):
                self.tick(snapshot)
        self.factory.assert_not_called()

    def test_folder_watcher_integration_uses_an_isolated_temporary_root(self):
        policies = [
            {"policy_id": pid, "action": action, "exit_points": ["USB"],
             "content_rules": [{"id": pid, "rule_name": marker, "pattern": marker,
                                "rule_type": "REGEX", "severity": "HIGH", "category": "INTERNAL_DOC"}]}
            for pid, marker, action in ((11, "ALPHA", "BLOCK"), (22, "BETA", "REPORT_ONLY"))
        ]
        snapshot = {"usb-test": usb_watcher.UsbDisk(3, ("F",))}
        events = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.factory.side_effect = lambda device, letter: usb_watcher.FolderWatcher(
                root, policies, events.append)
            self.tick(snapshot)
            files = {"clean.txt": "hello", "monitor.txt": "BETA", "blocked.txt": "ALPHA"}
            for name, text in files.items():
                (root / name).write_text(text, encoding="utf-8")
            self.tick(snapshot)
            self.assertEqual(events, [])
            self.tick(snapshot)
            self.tick(snapshot)
            self.assertEqual(sorted(path.name for path in root.iterdir()), ["clean.txt", "monitor.txt"])
        self.factory.assert_called_once_with("usb-test", "F")
        self.assertEqual(sorted((event["file_name"], event["action_taken"], event["policy_id"])
                                for event in events),
                         [("blocked.txt", "BLOCKED_DELETE", 11), ("monitor.txt", "LOGGED", 22)])
