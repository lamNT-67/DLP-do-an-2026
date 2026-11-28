"""Exercise USB identity and whitelist evaluation with synthetic snapshots."""

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from usb_identity import UsbDeviceIdentity, UsbWhitelistStatus, classify_usb_whitelist


class UsbWhitelistTests(unittest.TestCase):
    def setUp(self):
        self.disk = UsbDeviceIdentity("disk-a", " Lab-001 ", ("volume-a", "volume-b"))
        self.policy = {"usb_whitelist": [{"serial_number": "\tLab-001 ", "description": "Lab USB"}]}

    def test_trims_serials_and_matches_either_volume_on_the_same_disk(self):
        for volume_id in ("volume-a", " VOLUME-B "):
            with self.subTest(volume_id=volume_id):
                self.assertEqual(classify_usb_whitelist(volume_id, [self.disk], self.policy),
                                 UsbWhitelistStatus.LISTED)

    def test_serial_comparison_preserves_case_and_internal_characters(self):
        for serial in ("lab-001", "Lab- 001", "Lab-0011", "Lab-00"):
            with self.subTest(serial=serial):
                policy = {"usb_whitelist": [{"serial_number": serial}]}
                self.assertEqual(classify_usb_whitelist("volume-a", [self.disk], policy),
                                 UsbWhitelistStatus.UNLISTED)

    def test_group_assignment_does_not_control_whitelist_evaluation(self):
        policy = {**self.policy, "group_id": None, "is_assigned": False, "applicable_policies": []}
        self.assertEqual(classify_usb_whitelist("volume-a", [self.disk], policy),
                         UsbWhitelistStatus.LISTED)

    def test_duplicate_whitelist_serials_still_match(self):
        policy = {"usb_whitelist": [
            {"serial_number": "Lab-001", "description": "Global entry"},
            {"serial_number": " Lab-001 ", "description": "Group entry"},
        ]}
        self.assertEqual(classify_usb_whitelist("volume-a", [self.disk], policy),
                         UsbWhitelistStatus.LISTED)

    def test_empty_whitelist_leaves_known_identity_unlisted(self):
        self.assertEqual(classify_usb_whitelist("volume-a", [self.disk], {"usb_whitelist": []}),
                         UsbWhitelistStatus.UNLISTED)

    def test_missing_or_unknown_volume_is_identity_unknown(self):
        for volume_id in (None, " ", "volume-other"):
            with self.subTest(volume_id=volume_id):
                self.assertEqual(classify_usb_whitelist(volume_id, [self.disk], self.policy),
                                 UsbWhitelistStatus.IDENTITY_UNKNOWN)

    def test_missing_or_unusable_inventory_is_identity_unknown(self):
        for inventory in (None, [], [None, self.disk]):
            with self.subTest(inventory=inventory):
                self.assertEqual(classify_usb_whitelist("volume-a", inventory, self.policy),
                                 UsbWhitelistStatus.IDENTITY_UNKNOWN)

    def test_missing_physical_identity_or_serial_is_identity_unknown(self):
        for disk in (
            UsbDeviceIdentity(None, "Lab-001", ("volume-a",)),
            UsbDeviceIdentity(" ", "Lab-001", ("volume-a",)),
            UsbDeviceIdentity("disk:3", "Lab-001", ("volume-a",)),
            UsbDeviceIdentity("disk-a", None, ("volume-a",)),
            UsbDeviceIdentity("disk-a", "\t", ("volume-a",)),
        ):
            with self.subTest(disk=disk):
                self.assertEqual(classify_usb_whitelist("volume-a", [disk], self.policy),
                                 UsbWhitelistStatus.IDENTITY_UNKNOWN)

    def test_numeric_device_id_is_identity_unknown(self):
        for device_id in ("3", " 007 "):
            with self.subTest(device_id=device_id):
                disk = UsbDeviceIdentity(device_id, "Lab-001", ("volume-a",))
                self.assertEqual(classify_usb_whitelist("volume-a", [disk], self.policy),
                                 UsbWhitelistStatus.IDENTITY_UNKNOWN)

    def test_drive_letter_volume_id_is_identity_unknown(self):
        for volume_id in ("E", "e:", " E:\\ ", "E:/"):
            with self.subTest(volume_id=volume_id):
                disk = UsbDeviceIdentity("disk-a", "Lab-001", (volume_id,))
                self.assertEqual(classify_usb_whitelist(volume_id, [disk], self.policy),
                                 UsbWhitelistStatus.IDENTITY_UNKNOWN)

    def test_volume_claimed_by_two_disks_is_identity_unknown(self):
        other_disk = UsbDeviceIdentity("disk-b", "Lab-002", ("VOLUME-A",))
        self.assertEqual(classify_usb_whitelist("volume-a", [self.disk, other_disk], self.policy),
                         UsbWhitelistStatus.IDENTITY_UNKNOWN)

    def test_duplicate_volume_claim_on_one_disk_is_identity_unknown(self):
        disk = UsbDeviceIdentity("disk-a", "Lab-001", ("volume-a", "VOLUME-A"))
        self.assertEqual(classify_usb_whitelist("volume-a", [disk], self.policy),
                         UsbWhitelistStatus.IDENTITY_UNKNOWN)

    def test_duplicate_disk_id_within_snapshot_is_identity_unknown(self):
        duplicate = UsbDeviceIdentity(" DISK-A ", "Lab-002", ("volume-c",))
        for inventory in ([self.disk, duplicate], [self.disk, self.disk]):
            with self.subTest(inventory=inventory):
                self.assertEqual(classify_usb_whitelist("volume-a", inventory, self.policy),
                                 UsbWhitelistStatus.IDENTITY_UNKNOWN)

    def test_duplicate_serial_on_unmounted_disk_is_identity_unknown(self):
        other_disk = UsbDeviceIdentity("disk-b", "Lab-001\t", ())
        self.assertEqual(classify_usb_whitelist("volume-a", [self.disk, other_disk], self.policy),
                         UsbWhitelistStatus.IDENTITY_UNKNOWN)

    def test_missing_or_malformed_whitelist_is_unavailable(self):
        for policy in (
            None, [], {}, {"usb_whitelist": None}, {"usb_whitelist": {}},
            {"usb_whitelist": "Lab-001"}, {"usb_whitelist": ["Lab-001"]},
            {"usb_whitelist": [{}]}, {"usb_whitelist": [{"serial_number": 123}]},
            {"usb_whitelist": [{"serial_number": " "}]},
            {"usb_whitelist": [{"serial_number": "Lab-001"}, None]},
        ):
            with self.subTest(policy=policy):
                self.assertEqual(classify_usb_whitelist("volume-a", [self.disk], policy),
                                 UsbWhitelistStatus.WHITELIST_UNAVAILABLE)

    def test_unavailable_whitelist_takes_precedence_over_unknown_identity(self):
        self.assertEqual(classify_usb_whitelist(None, None, {}),
                         UsbWhitelistStatus.WHITELIST_UNAVAILABLE)
        self.assertEqual(classify_usb_whitelist(None, None, {"usb_whitelist": []}),
                         UsbWhitelistStatus.IDENTITY_UNKNOWN)

    def test_each_call_uses_the_current_inventory_and_policy(self):
        replacement = UsbDeviceIdentity("disk-b", "Lab-002", ("volume-a",))
        self.assertEqual(classify_usb_whitelist("volume-a", [self.disk], self.policy),
                         UsbWhitelistStatus.LISTED)
        self.assertEqual(classify_usb_whitelist("volume-a", [replacement], self.policy),
                         UsbWhitelistStatus.UNLISTED)
        self.assertEqual(classify_usb_whitelist("volume-a", [self.disk], None),
                         UsbWhitelistStatus.WHITELIST_UNAVAILABLE)
        self.assertEqual(classify_usb_whitelist("volume-a", [self.disk], {"usb_whitelist": []}),
                         UsbWhitelistStatus.UNLISTED)
