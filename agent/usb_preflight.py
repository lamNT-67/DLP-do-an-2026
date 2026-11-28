"""Collect Windows USB identity metadata and diagnose a selected destination."""

import argparse
import configparser
from contextlib import redirect_stdout
import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import json
import ntpath
import os
import re
import stat
import subprocess
import sys

from usb_identity import UsbDeviceIdentity, UsbWhitelistStatus, classify_usb_whitelist


_INVENTORY_TIMEOUT = 15
_MAX_DISKS = 128
_MAX_PARTITIONS = 1024
_MAX_INVENTORY_BYTES = 2 * 1024 * 1024

# Read one extra row so that an inventory at the limit is never silently truncated.
_STORAGE_QUERY = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
function Read-Disks {
    Storage\Get-Disk | Select-Object -First %d -Property Number, Path, SerialNumber, IsBoot, IsSystem, IsOffline,
        @{Name='BusType'; Expression={[string]$_.BusType}}
}
try {
    $before = @(Read-Disks)
    $partitions = @(Storage\Get-Partition | Select-Object -First %d -Property DiskNumber, PartitionNumber, AccessPaths)
    $after = @(Read-Disks)
    ConvertTo-Json -InputObject @{disks=$before; partitions=$partitions; disks_after=$after} -Depth 5 -Compress
} catch {
    if ($_.CategoryInfo.Category -in 'PermissionDenied', 'SecurityError' -or
        $_.Exception -is [System.UnauthorizedAccessException] -or
        $_.Exception.NativeErrorCode -eq 'AccessDenied' -or
        $_.FullyQualifiedErrorId -match '0x80070005|0x80041003') {
        exit 10
    }
    exit 11
}
""" % (_MAX_DISKS + 1, _MAX_PARTITIONS + 1)

_VOLUME_NAME = re.compile(
    r"(\\\\\?\\volume\{[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\})(?=\\|$)",
    re.IGNORECASE | re.ASCII,
)
_DISK_INTERFACE_PATH = re.compile(
    r"\\\\\?\\[^\\/]+#\{53f56307-b6bf-11d0-94f2-00a0c91efb8b\}", re.IGNORECASE | re.ASCII
)
_DRIVE_PATH = re.compile(r'[a-zA-Z]:\\[^:\x00-\x1f<>"|?*]*')

_FILE_READ_ATTRIBUTES = 0x0080
_SHARE_ALL = 0x0007
_OPEN_EXISTING = 3
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_ATTRIBUTE_TAG_INFO = 9
_VOLUME_NAME_GUID = 1
_INVALID_HANDLE = ctypes.c_void_p(-1).value


class UsbPreflightError(RuntimeError):
    """A stable diagnostic for an inventory or destination lookup failure."""


@dataclass(frozen=True)
class UsbDestinationPreflight:
    status: UsbWhitelistStatus
    volume_id: str | None = None
    diagnostic: str | None = None


@dataclass(frozen=True)
class _Disk:
    path: str | None
    serial: str | None
    bus_type: str
    is_boot: bool
    is_system: bool
    is_offline: bool


def _records(snapshot, key, limit):
    records = snapshot[key]
    if not isinstance(records, list) or any(not isinstance(row, dict) for row in records):
        raise ValueError("Invalid inventory records")
    if len(records) > limit:
        raise UsbPreflightError("INVENTORY_LIMIT_EXCEEDED")
    return records


def _storage_number(value):
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("Invalid storage number")
    return value


def _metadata_text(value):
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("Invalid storage metadata")
    value = value.strip()
    if value and not value.isprintable():
        raise ValueError("Invalid storage metadata")
    return value or None


def _parse_disks(records):
    disks = {}
    paths = set()
    for row in records:
        number = _storage_number(row["Number"])
        path = _metadata_text(row["Path"])
        path = path.casefold() if path else None
        serial = _metadata_text(row["SerialNumber"])
        bus_type = _metadata_text(row["BusType"])
        flags = (row["IsBoot"], row["IsSystem"], row["IsOffline"])
        if bus_type is None or any(type(flag) is not bool for flag in flags):
            raise ValueError("Invalid disk eligibility metadata")
        if number in disks or path in paths:
            raise UsbPreflightError("INVENTORY_AMBIGUOUS")
        if path is not None:
            paths.add(path)
        disks[number] = _Disk(path, serial, bus_type.casefold(), *flags)
    return disks


def _parse_inventory(snapshot):
    disks = _parse_disks(_records(snapshot, "disks", _MAX_DISKS))
    disks_after = _parse_disks(_records(snapshot, "disks_after", _MAX_DISKS))
    if disks != disks_after:
        raise UsbPreflightError("INVENTORY_CHANGED")

    volumes = {number: [] for number in disks}
    partitions = set()
    for row in _records(snapshot, "partitions", _MAX_PARTITIONS):
        disk_number = _storage_number(row["DiskNumber"])
        partition = disk_number, _storage_number(row["PartitionNumber"])
        if disk_number not in disks or partition in partitions:
            raise UsbPreflightError("INVENTORY_AMBIGUOUS")
        partitions.add(partition)

        access_paths = row["AccessPaths"]
        if access_paths is None:
            continue
        if not isinstance(access_paths, list):
            raise ValueError("Invalid partition access paths")
        for path in access_paths:
            if not isinstance(path, str) or not path.isprintable():
                raise ValueError("Invalid partition access path")
            match = _VOLUME_NAME.fullmatch(path.removesuffix("\\"))
            if match:
                volumes[disk_number].append(match[1].casefold() + "\\")
            elif path.casefold().startswith("\\\\?\\volume"):
                raise ValueError("Invalid volume GUID")

    inventory = []
    for number, disk in disks.items():
        device_id = None
        if (disk.bus_type in {"usb", "7"} and not (disk.is_boot or disk.is_system or disk.is_offline)
                and disk.path and _DISK_INTERFACE_PATH.fullmatch(disk.path)):
            device_id = disk.path
        # Keep claims and serials from every disk so an excluded disk cannot hide a collision.
        inventory.append(UsbDeviceIdentity(device_id, disk.serial, tuple(volumes[number])))
    return tuple(inventory)


def collect_windows_usb_inventory() -> tuple[UsbDeviceIdentity, ...]:
    """Return observed disk identities for the classifier, or raise UsbPreflightError."""
    if sys.platform != "win32":
        raise UsbPreflightError("UNSUPPORTED_PLATFORM")
    powershell = ntpath.join(os.environ.get("SystemRoot", r"C:\Windows"),
                             "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    try:
        result = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-Command", _STORAGE_QUERY],
            capture_output=True, check=True, timeout=_INVENTORY_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        raise UsbPreflightError("INVENTORY_TIMEOUT") from None
    except PermissionError:
        raise UsbPreflightError("INVENTORY_ACCESS_DENIED") from None
    except subprocess.CalledProcessError as error:
        diagnostic = "INVENTORY_ACCESS_DENIED" if error.returncode == 10 else "INVENTORY_QUERY_FAILED"
        raise UsbPreflightError(diagnostic) from None
    except OSError:
        raise UsbPreflightError("INVENTORY_QUERY_FAILED") from None

    if len(result.stdout) > _MAX_INVENTORY_BYTES:
        raise UsbPreflightError("INVENTORY_LIMIT_EXCEEDED")
    try:
        snapshot = json.loads(result.stdout)
        if not isinstance(snapshot, dict):
            raise ValueError("Invalid inventory object")
        return _parse_inventory(snapshot)
    except (KeyError, ValueError, RecursionError):
        raise UsbPreflightError("INVENTORY_INVALID") from None


def _bind(dll, name, restype, *argtypes):
    function = getattr(dll, name)
    function.restype = restype
    function.argtypes = argtypes
    return function


def _directory_volume(path):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    handle, word, wide = wintypes.HANDLE, wintypes.DWORD, wintypes.LPCWSTR
    drive_type = _bind(kernel, "GetDriveTypeW", wintypes.UINT, wide)
    if drive_type(path[:3]) not in {2, 3}:  # A local removable or fixed drive.
        raise UsbPreflightError("DESTINATION_UNSUPPORTED")
    open_existing = _bind(kernel, "CreateFileW", handle, wide, word, word,
                          wintypes.LPVOID, word, word, handle)
    get_info = _bind(kernel, "GetFileInformationByHandleEx", wintypes.BOOL,
                     handle, ctypes.c_int, wintypes.LPVOID, word)
    final_path = _bind(kernel, "GetFinalPathNameByHandleW", word,
                       handle, wintypes.LPWSTR, word, word)
    close = _bind(kernel, "CloseHandle", wintypes.BOOL, handle)

    directory = open_existing(path, _FILE_READ_ATTRIBUTES, _SHARE_ALL, None,
                              _OPEN_EXISTING, _FILE_FLAG_BACKUP_SEMANTICS, None)
    if directory == _INVALID_HANDLE:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        attributes = (word * 2)()  # FILE_ATTRIBUTE_TAG_INFO
        if not get_info(directory, _FILE_ATTRIBUTE_TAG_INFO, attributes, ctypes.sizeof(attributes)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not attributes[0] & stat.FILE_ATTRIBUTE_DIRECTORY:
            raise UsbPreflightError("DESTINATION_NOT_DIRECTORY")
        buffer = ctypes.create_unicode_buffer(32768)
        length = final_path(directory, buffer, len(buffer), _VOLUME_NAME_GUID)
        if length == 0:
            raise ctypes.WinError(ctypes.get_last_error())
        match = _VOLUME_NAME.match(buffer.value) if length < len(buffer) else None
        if match is None:
            raise UsbPreflightError("DESTINATION_UNSUPPORTED")
        return match[1].casefold() + "\\"
    finally:
        close(directory)


def preflight_usb_destination(destination: str | os.PathLike[str],
                              policy_response: object) -> UsbDestinationPreflight:
    """Diagnose membership for an existing Windows directory using a fresh snapshot."""
    try:
        if sys.platform != "win32":
            raise UsbPreflightError("UNSUPPORTED_PLATFORM")
        try:
            path = os.fspath(destination)
        except TypeError:
            raise UsbPreflightError("DESTINATION_INVALID") from None
        if not isinstance(path, str) or not _DRIVE_PATH.fullmatch(path.replace("/", "\\")):
            raise UsbPreflightError("DESTINATION_INVALID")
        path = ntpath.normpath(path)
        volume_id = _directory_volume(path)
        inventory = collect_windows_usb_inventory()
        if _directory_volume(path) != volume_id:
            raise UsbPreflightError("DESTINATION_CHANGED")
    except UsbPreflightError as error:
        diagnostic = str(error)
    except PermissionError:
        diagnostic = "DESTINATION_ACCESS_DENIED"
    except OSError as error:
        diagnostic = "DESTINATION_UNAVAILABLE"
        if isinstance(error, TimeoutError) or getattr(error, "winerror", None) in {121, 1460}:
            diagnostic = "DESTINATION_TIMEOUT"
    else:
        status = classify_usb_whitelist(volume_id, inventory, policy_response)
        diagnostic = "IDENTITY_UNVERIFIED" if status is UsbWhitelistStatus.IDENTITY_UNKNOWN else None
        return UsbDestinationPreflight(status, volume_id, diagnostic)
    return UsbDestinationPreflight(classify_usb_whitelist(None, None, policy_response), diagnostic=diagnostic)


def _read_policy(config_path):
    from policy_client import PolicyClient

    config = configparser.ConfigParser(interpolation=None)
    with open(config_path, encoding="utf-8-sig") as stream:
        config.read_file(stream)
    agent = config["agent"]
    settings = [agent[key].strip() for key in ("server_url", "hostname", "api_token")]
    if not all(settings):
        raise ValueError("Incomplete agent configuration")
    with redirect_stdout(sys.stderr):
        return PolicyClient(*settings).get_policy()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", help="Existing directory on a Windows drive")
    parser.add_argument("--config", help="Registered agent INI for an optional policy GET")
    args = parser.parse_args(argv)
    policy_response = None
    if args.config:
        try:
            policy_response = _read_policy(args.config)
        except (OSError, KeyError, ValueError, configparser.Error):
            parser.error("Cannot read registered agent configuration or policy response.")
    result = preflight_usb_destination(args.destination, policy_response)
    print(json.dumps({
        "status": result.status.value,
        "volume_id": result.volume_id,
        "diagnostic": result.diagnostic,
    }))


if __name__ == "__main__":
    main()
