"""Validate synthetic or collected USB identities and evaluate whitelist membership."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
import re


@dataclass(frozen=True)
class UsbDeviceIdentity:
    """One physical disk in an inventory snapshot, with its stable volume IDs."""

    device_id: str | None
    serial_number: str | None
    volume_ids: tuple[str, ...]


class UsbWhitelistStatus(str, Enum):
    LISTED = "LISTED"
    UNLISTED = "UNLISTED"
    IDENTITY_UNKNOWN = "IDENTITY_UNKNOWN"
    WHITELIST_UNAVAILABLE = "WHITELIST_UNAVAILABLE"


def _trimmed_text(value: object) -> str | None:
    return (value.strip() or None) if isinstance(value, str) else None


def _identity_key(value: object) -> str | None:
    text = _trimmed_text(value)
    if text is None:
        return None
    key = text.casefold()
    if key.isdecimal() or re.fullmatch(r"[a-z](?::[\\/]?)?", key):
        return None
    return key


def _whitelist_serials(policy_response: object) -> set[str] | None:
    if not isinstance(policy_response, Mapping):
        return None
    records = policy_response.get("usb_whitelist")
    if not isinstance(records, list):
        return None

    serials = set()
    for record in records:
        if not isinstance(record, Mapping):
            return None
        serial = _trimmed_text(record.get("serial_number"))
        if serial is None:
            return None
        serials.add(serial)
    return serials


def _verified_serial(
    volume_id: str | None, inventory: Sequence[UsbDeviceIdentity] | None
) -> str | None:
    volume_key = _identity_key(volume_id)
    if volume_key is None or not isinstance(inventory, Sequence):
        return None
    if any(not isinstance(disk, UsbDeviceIdentity) or not isinstance(disk.volume_ids, tuple)
           for disk in inventory):
        return None

    owners = [disk for disk in inventory for mounted_volume in disk.volume_ids
              if _identity_key(mounted_volume) == volume_key]
    if len(owners) != 1:
        return None

    owner = owners[0]
    device_key = _identity_key(owner.device_id)
    serial = _trimmed_text(owner.serial_number)
    if device_key is None or device_key.startswith("disk:") or serial is None:
        return None
    if serial.casefold() in {"unknown", "n/a"} or re.fullmatch(r"0+", serial):
        return None

    if sum(_identity_key(disk.device_id) == device_key for disk in inventory) != 1:
        return None
    if sum(_trimmed_text(disk.serial_number) == serial for disk in inventory) != 1:
        return None
    return serial


def classify_usb_whitelist(
    volume_id: str | None,
    inventory: Sequence[UsbDeviceIdentity] | None,
    policy_response: object,
) -> UsbWhitelistStatus:
    """Classify a volume against one inventory snapshot and one policy response.

    The caller supplies disk identities and volume IDs, such as volume GUIDs.
    Disk numbers and drive letters are transient locators. An unavailable
    whitelist takes precedence over identity diagnostics.
    """
    serials = _whitelist_serials(policy_response)
    if serials is None:
        return UsbWhitelistStatus.WHITELIST_UNAVAILABLE
    serial = _verified_serial(volume_id, inventory)
    if serial is None:
        return UsbWhitelistStatus.IDENTITY_UNKNOWN
    if serial in serials:
        return UsbWhitelistStatus.LISTED
    return UsbWhitelistStatus.UNLISTED
