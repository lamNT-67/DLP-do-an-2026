"""Synthetic tests for USB device detection and the command modes."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import usb_watcher


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
