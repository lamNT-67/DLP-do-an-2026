"""Synthetic tests of USB destination preflight and its read-only boundaries."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, call, mock_open, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import usb_preflight as usb
from usb_identity import UsbDeviceIdentity, UsbWhitelistStatus


VOLUME_A = "\\\\?\\Volume{32ab4e0b-3ad0-4adf-9828-c28fbe3467cc}\\"
VOLUME_B = "\\\\?\\Volume{c023e7c4-99ac-4c7d-a824-1c1a8ec46490}\\"
DESTINATION = r"F:\Lab [review] $sample"
POLICY = {"is_assigned": False, "usb_whitelist": [{"serial_number": " LAB-001 "}]}


def disk(number=4, **properties):
    return {
        "Number": number,
        "Path": rf"\\?\USBSTOR#Disk&Ven_Lab#media-{number}#{{53f56307-b6bf-11d0-94f2-00a0c91efb8b}}",
        "SerialNumber": f"LAB-{number:03d}" if number != 4 else " LAB-001 ",
        "BusType": "USB",
        "IsBoot": False,
        "IsSystem": False,
        "IsOffline": False,
        **properties,
    }


def partition(disk_number, *paths, number=1):
    return {"DiskNumber": disk_number, "PartitionNumber": number, "AccessPaths": list(paths)}


def snapshot(disks=None, partitions=None):
    disks = [disk()] if disks is None else disks
    partitions = [partition(4, "F:\\", VOLUME_A)] if partitions is None else partitions
    return {"disks": disks, "partitions": partitions, "disks_after": disks[::-1]}


class UsbPreflightTests(unittest.TestCase):
    def setUp(self):
        self.kernel = Mock(spec=["GetDriveTypeW", "CreateFileW", "GetFileInformationByHandleEx",
                                 "GetFinalPathNameByHandleW", "CloseHandle"])
        self.kernel.GetDriveTypeW.return_value = 3
        self.kernel.CreateFileW.return_value = 42
        self.kernel.GetFileInformationByHandleEx.side_effect = self._directory_attributes
        self._final_paths(VOLUME_A.upper() + "destination")
        self.run = Mock()
        self._provider(snapshot())
        for mock in (
            patch.object(usb.sys, "platform", "win32"),
            patch.object(usb.ctypes, "WinDLL", return_value=self.kernel, create=True),
            patch.object(usb.subprocess, "run", self.run),
        ):
            mock.start()
            self.addCleanup(mock.stop)

    @staticmethod
    def _directory_attributes(handle, info_class, attributes, size):
        attributes[0] = stat.FILE_ATTRIBUTE_DIRECTORY
        return 1

    def _final_paths(self, *paths):
        responses = iter(paths) if len(paths) > 1 else None

        def final_path(handle, buffer, capacity, flags):
            path = next(responses) if responses is not None else paths[0]
            buffer.value = path
            return len(path)

        self.kernel.GetFinalPathNameByHandleW.side_effect = final_path

    def _provider(self, data):
        self.run.return_value = subprocess.CompletedProcess(
            "mock PowerShell", 0, stdout=json.dumps(data).encode("utf-8"), stderr=b"",
        )

    def _expect(self, status, diagnostic=None, *, destination=DESTINATION, policy=POLICY):
        result = usb.preflight_usb_destination(destination, policy)
        self.assertEqual(result.status, status)
        self.assertEqual(result.diagnostic, diagnostic)
        return result

    def test_resolves_final_volume_and_uses_read_only_metadata_calls(self):
        result = self._expect(UsbWhitelistStatus.LISTED)
        self.assertEqual(result.volume_id, VOLUME_A.casefold())
        self.assertEqual(self.kernel.GetDriveTypeW.call_args_list, [call("F:\\")] * 2)
        self.assertEqual(self.kernel.CreateFileW.call_args_list, [
            call(DESTINATION, 0x0080, 0x0007, None, 3, 0x02000000, None),
        ] * 2)
        self.assertEqual([c.args[1] for c in self.kernel.GetFileInformationByHandleEx.call_args_list], [9, 9])
        self.assertEqual([c.args[3] for c in self.kernel.GetFinalPathNameByHandleW.call_args_list], [1, 1])
        self.assertEqual(self.kernel.CloseHandle.call_args_list, [call(42)] * 2)
        self.run.assert_called_once()
        command = self.run.call_args.args[0]
        self.assertEqual(command[1:4], ["-NoProfile", "-NonInteractive", "-Command"])
        self.assertTrue(command[0].endswith(r"\WindowsPowerShell\v1.0\powershell.exe"))
        self.assertIn(r"Storage\Get-Disk", command[-1])
        self.assertIn(r"Storage\Get-Partition", command[-1])
        self.assertTrue(all(DESTINATION not in arg for arg in command))
        self.assertNotIn("-ExecutionPolicy", command)
        self.assertEqual(self.run.call_args.kwargs, {"capture_output": True, "check": True, "timeout": 15})

    def test_groups_multiple_volumes_by_physical_disk(self):
        source = disk(BusType="7")
        self._provider(snapshot([source], [
            partition(4, "F:\\", VOLUME_A),
            partition(4, r"C:\Mount\Lab", VOLUME_B.rstrip("\\"), number=2),
        ]))
        self.assertEqual(usb.collect_windows_usb_inventory(), (
            UsbDeviceIdentity(source["Path"].casefold(), "LAB-001", (VOLUME_A.casefold(), VOLUME_B.casefold())),
        ))
        self._final_paths(VOLUME_B + "nested")
        result = self._expect(UsbWhitelistStatus.LISTED, destination=r"C:\Mount\Lab\nested")
        self.assertEqual(result.volume_id, VOLUME_B.casefold())

    def test_reassignment_preserves_volume_identity_and_reused_letter_is_rechecked(self):
        first = self._expect(UsbWhitelistStatus.LISTED)
        media = disk()
        self._provider(snapshot([{**media, "Number": 8}], [partition(8, "J:\\", VOLUME_A)]))
        moved = self._expect(UsbWhitelistStatus.LISTED, destination=r"J:\Lab")
        self.assertEqual(moved.volume_id, first.volume_id)

        self._provider(snapshot([disk(5)], [partition(5, "F:\\", VOLUME_B)]))
        self._final_paths(VOLUME_B)
        new_media = self._expect(UsbWhitelistStatus.UNLISTED)
        self.assertNotEqual(new_media.volume_id, first.volume_id)

    def test_valid_empty_or_nonmatching_whitelist_is_unlisted(self):
        for records in ([], [{"serial_number": "lab-001"}]):
            with self.subTest(records=records):
                self._expect(UsbWhitelistStatus.UNLISTED, policy={"usb_whitelist": records})

    def test_missing_or_malformed_whitelist_is_unavailable(self):
        for response in (None, {}, {"usb_whitelist": ["LAB-001"]}):
            with self.subTest(response=response):
                self._expect(UsbWhitelistStatus.WHITELIST_UNAVAILABLE, policy=response)

    def test_duplicate_serial_on_unmounted_disk_is_unknown(self):
        self._provider(snapshot([disk(), disk(5, SerialNumber="LAB-001")]))
        self._expect(UsbWhitelistStatus.IDENTITY_UNKNOWN, "IDENTITY_UNVERIFIED")

    def test_missing_serial_is_unknown(self):
        for serial in (None, "", "  "):
            with self.subTest(serial=serial):
                self._provider(snapshot([disk(SerialNumber=serial)]))
                self._expect(UsbWhitelistStatus.IDENTITY_UNKNOWN, "IDENTITY_UNVERIFIED")

    def test_whitelisted_placeholder_serial_is_unknown(self):
        for serial in ("00000000", "UNKNOWN", "N/A"):
            with self.subTest(serial=serial):
                self._provider(snapshot([disk(SerialNumber=serial)]))
                policy = {"usb_whitelist": [{"serial_number": serial}]}
                self._expect(UsbWhitelistStatus.IDENTITY_UNKNOWN, "IDENTITY_UNVERIFIED", policy=policy)

    def test_drive_letter_alone_does_not_correlate_volume(self):
        self._provider(snapshot(partitions=[partition(4, "F:\\")]))
        self._expect(UsbWhitelistStatus.IDENTITY_UNKNOWN, "IDENTITY_UNVERIFIED")

    def test_ambiguous_volume_claims_are_unknown_even_with_an_excluded_owner(self):
        for other in (disk(5), disk(5, BusType="SATA")):
            with self.subTest(other=other["BusType"]):
                self._provider(snapshot([disk(), other], [
                    partition(4, "F:\\", VOLUME_A),
                    partition(5, "J:\\", VOLUME_A.upper()),
                ]))
                self._expect(UsbWhitelistStatus.IDENTITY_UNKNOWN, "IDENTITY_UNVERIFIED")

    def test_duplicate_or_orphaned_inventory_rows_are_rejected(self):
        for data in (
            snapshot([disk(), disk(SerialNumber="different")]),
            snapshot([disk(), disk(5, Path=disk()["Path"].upper())]),
            snapshot(partitions=[partition(4, VOLUME_A), partition(4, VOLUME_B)]),
            snapshot(partitions=[partition(91, VOLUME_A)]),
        ):
            with self.subTest(data=data):
                self._provider(data)
                self._expect(UsbWhitelistStatus.IDENTITY_UNKNOWN, "INVENTORY_AMBIGUOUS")

    def test_boot_system_offline_non_usb_and_transient_disk_paths_are_excluded(self):
        for changes in (
            {"IsBoot": True}, {"IsSystem": True}, {"IsOffline": True}, {"BusType": "NVMe"},
            {"BusType": "Virtual"}, {"Path": None}, {"Path": "disk:4"}, {"Path": r"\\?\PhysicalDrive4"},
        ):
            with self.subTest(changes=changes):
                self._provider(snapshot([disk(**changes)]))
                self._expect(UsbWhitelistStatus.IDENTITY_UNKNOWN, "IDENTITY_UNVERIFIED")

    def test_malformed_inventory_is_reported_explicitly(self):
        for data in (
            [], {}, snapshot([disk(IsBoot="false")]), snapshot([disk(Number=True)]),
            snapshot([disk(SerialNumber=7)]), snapshot([disk(SerialNumber="LAB\x00")]),
            snapshot(partitions=[{"DiskNumber": 4, "PartitionNumber": 1, "AccessPaths": VOLUME_A}]),
            snapshot(partitions=[partition(4, "\\\\?\\Volume{not-a-guid}\\")]),
        ):
            with self.subTest(data=data):
                self._provider(data)
                self._expect(UsbWhitelistStatus.IDENTITY_UNKNOWN, "INVENTORY_INVALID")
        self.run.return_value.stdout = b"{"
        self._expect(UsbWhitelistStatus.IDENTITY_UNKNOWN, "INVENTORY_INVALID")

    def test_inventory_row_and_payload_limits_reject_partial_evidence(self):
        for name, limit in (("_MAX_DISKS", 0), ("_MAX_PARTITIONS", 0), ("_MAX_INVENTORY_BYTES", 32)):
            with self.subTest(limit=name), patch.object(usb, name, limit):
                self._expect(UsbWhitelistStatus.IDENTITY_UNKNOWN, "INVENTORY_LIMIT_EXCEEDED")

    def test_disk_number_reuse_during_inventory_is_unknown(self):
        data = snapshot()
        data["disks_after"] = [disk(Path=disk(5)["Path"], SerialNumber="LAB-005")]
        self._provider(data)
        self._expect(UsbWhitelistStatus.IDENTITY_UNKNOWN, "INVENTORY_CHANGED")

    def test_destination_change_during_inventory_is_unknown(self):
        self._final_paths(VOLUME_A, VOLUME_B)
        result = self._expect(UsbWhitelistStatus.IDENTITY_UNKNOWN, "DESTINATION_CHANGED")
        self.assertIsNone(result.volume_id)
        self.assertEqual(self.kernel.CloseHandle.call_args_list, [call(42)] * 2)

    def test_inventory_failures_have_distinct_diagnostics(self):
        for error, diagnostic in (
            (PermissionError("denied"), "INVENTORY_ACCESS_DENIED"),
            (subprocess.CalledProcessError(10, "mock PowerShell"), "INVENTORY_ACCESS_DENIED"),
            (subprocess.CalledProcessError(11, "mock PowerShell"), "INVENTORY_QUERY_FAILED"),
            (OSError("missing program"), "INVENTORY_QUERY_FAILED"),
            (subprocess.TimeoutExpired("mock PowerShell", 15), "INVENTORY_TIMEOUT"),
        ):
            with self.subTest(error=error):
                self.run.side_effect = error
                result = self._expect(UsbWhitelistStatus.IDENTITY_UNKNOWN, diagnostic)
                self.assertIsNone(result.volume_id)
                self._expect(UsbWhitelistStatus.WHITELIST_UNAVAILABLE, diagnostic, policy=None)

    def test_invalid_or_remote_paths_do_not_open_destination_or_query_storage(self):
        for path in (r"relative\dir", "F:", r"\\server\share\dir", r"\\.\PhysicalDrive4", "F:\\bad\x00"):
            with self.subTest(path=path):
                self._expect(UsbWhitelistStatus.IDENTITY_UNKNOWN, "DESTINATION_INVALID", destination=path)
        self.kernel.GetDriveTypeW.return_value = 4
        self._expect(UsbWhitelistStatus.IDENTITY_UNKNOWN, "DESTINATION_UNSUPPORTED")
        self.kernel.CreateFileW.assert_not_called()
        self.run.assert_not_called()

    def test_non_windows_does_not_open_destination_or_query_storage(self):
        with patch.object(usb.sys, "platform", "linux"):
            self._expect(UsbWhitelistStatus.IDENTITY_UNKNOWN, "UNSUPPORTED_PLATFORM")
        self.kernel.CreateFileW.assert_not_called()
        self.run.assert_not_called()

    def test_destination_permission_and_missing_path_errors(self):
        self.kernel.CreateFileW.return_value = usb._INVALID_HANDLE
        for error, diagnostic in (
            (PermissionError("denied"), "DESTINATION_ACCESS_DENIED"),
            (FileNotFoundError("missing"), "DESTINATION_UNAVAILABLE"),
            (TimeoutError("device timed out"), "DESTINATION_TIMEOUT"),
        ):
            with self.subTest(error=error), \
                    patch.object(usb.ctypes, "get_last_error", return_value=5, create=True), \
                    patch.object(usb.ctypes, "WinError", return_value=error, create=True):
                self._expect(UsbWhitelistStatus.IDENTITY_UNKNOWN, diagnostic)
        self.kernel.CloseHandle.assert_not_called()
        self.run.assert_not_called()

    def test_file_or_unresolvable_final_volume_is_rejected_and_handle_is_closed(self):
        self.kernel.GetFileInformationByHandleEx.side_effect = None
        self.kernel.GetFileInformationByHandleEx.return_value = 1
        self._expect(UsbWhitelistStatus.IDENTITY_UNKNOWN, "DESTINATION_NOT_DIRECTORY")

        self.kernel.GetFileInformationByHandleEx.side_effect = self._directory_attributes
        self._final_paths(r"\\?\UNC\server\share\destination")
        self._expect(UsbWhitelistStatus.IDENTITY_UNKNOWN, "DESTINATION_UNSUPPORTED")
        self.assertEqual(self.kernel.CloseHandle.call_args_list, [call(42)] * 2)
        self.run.assert_not_called()

    @unittest.skipUnless(os.name == "nt", "requires a Windows path for the synthetic destination")
    def test_preflight_leaves_synthetic_directory_and_file_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)
            sentinel = destination / "unchanged.txt"
            sentinel.write_bytes(b"synthetic test contents")
            modified_at = sentinel.stat().st_mtime_ns
            forbidden = Mock(side_effect=AssertionError("preflight attempted filesystem I/O"))
            with patch("builtins.open", forbidden), patch("io.open", forbidden), \
                    patch.multiple(os, open=forbidden, unlink=forbidden, remove=forbidden,
                                   mkdir=forbidden, rmdir=forbidden, rename=forbidden, replace=forbidden):
                self._expect(UsbWhitelistStatus.LISTED, destination=destination)
            self.assertEqual(list(destination.iterdir()), [sentinel])
            self.assertEqual(sentinel.read_bytes(), b"synthetic test contents")
            self.assertEqual(sentinel.stat().st_mtime_ns, modified_at)

    def test_cli_diagnostics_without_config_do_not_fetch_policy(self):
        output = io.StringIO()
        with patch.object(usb, "_read_policy") as load_policy, redirect_stdout(output):
            usb.main([DESTINATION])
        load_policy.assert_not_called()
        self.assertEqual(json.loads(output.getvalue()), {
            "status": "WHITELIST_UNAVAILABLE", "volume_id": VOLUME_A.casefold(), "diagnostic": None,
        })

    def test_configured_cli_uses_existing_policy_client_get_only(self):
        config = "[agent]\nserver_url = https://dlp.example/api\nhostname = TEST\napi_token = synthetic\n"
        client = Mock()
        client.get_policy.return_value = POLICY
        output = io.StringIO()
        with patch("builtins.open", mock_open(read_data=config)) as read, \
                patch("policy_client.PolicyClient", return_value=client) as client_class, redirect_stdout(output):
            usb.main([DESTINATION, "--config", "synthetic.ini"])
        read.assert_called_once_with("synthetic.ini", encoding="utf-8-sig")
        client_class.assert_called_once_with("https://dlp.example/api", "TEST", "synthetic")
        self.assertEqual(client.mock_calls, [call.get_policy()])
        self.assertEqual(json.loads(output.getvalue())["status"], "LISTED")

    def test_cli_keeps_fetch_errors_off_json_output(self):
        def failed_fetch():
            print("mock policy lookup failed")
            return None

        config = "[agent]\nserver_url = https://dlp.example/api\nhostname = TEST\napi_token = synthetic\n"
        client = Mock()
        client.get_policy.side_effect = failed_fetch
        output, errors = io.StringIO(), io.StringIO()
        with patch("builtins.open", mock_open(read_data=config)), \
                patch("policy_client.PolicyClient", return_value=client), \
                redirect_stdout(output), redirect_stderr(errors):
            usb.main([DESTINATION, "--config", "synthetic.ini"])
        self.assertEqual(json.loads(output.getvalue())["status"], "WHITELIST_UNAVAILABLE")
        self.assertIn("mock policy lookup failed", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
