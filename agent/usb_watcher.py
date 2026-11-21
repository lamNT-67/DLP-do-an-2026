"""List Windows USB disks or run the isolated USB folder simulation."""
import argparse
import configparser
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

from content_inspection import inspect_file, to_report_fields
from policy_utils import get_exit_point_status


WINDOWS_STORAGE_QUERY = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$disks = @(Get-Disk | Select-Object Number, Path, IsBoot, IsSystem,
    @{Name='BusType'; Expression={[string]$_.BusType}})
$partitions = @(Get-Partition | Select-Object DiskNumber,
    @{Name='DriveLetter'; Expression={[string]$_.DriveLetter}})
ConvertTo-Json -InputObject @{disks=$disks; partitions=$partitions} -Compress
"""


@dataclass(frozen=True)
class UsbDisk:
    number: int
    drive_letters: tuple[str, ...]


def usb_disks_from_storage(disks, partitions):
    """Index USB data disks with drive letters by Windows device path."""
    letters_by_number = {}
    for partition in partitions:
        letter = partition["DriveLetter"] or ""
        if re.fullmatch(r"[A-Za-z]", letter):
            letters_by_number.setdefault(partition["DiskNumber"], set()).add(letter.upper())

    usb_disks = {}
    numbers_by_path = {}
    for disk in disks:
        path = disk.get("Path")
        if path:
            key = path.casefold()
            number = disk["Number"]
            previous_number = numbers_by_path.setdefault(key, number)
            if previous_number != number:
                raise ValueError(f"Duplicate physical disk path for disks {previous_number} and {number}")
        if disk["BusType"].upper() != "USB" or disk["IsBoot"] or disk["IsSystem"]:
            continue
        number = disk["Number"]
        letters = letters_by_number.get(number)
        if letters:
            device = path or f"disk:{number}"
            usb_disks[device.casefold()] = UsbDisk(number, tuple(sorted(letters)))
    return usb_disks


def scan_windows_usb():
    """Read Windows storage metadata without opening or changing any volume."""
    if sys.platform != "win32":
        raise RuntimeError("--list-usb requires Windows")
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", WINDOWS_STORAGE_QUERY],
            capture_output=True, encoding="utf-8", check=True, timeout=30,
        )
        storage = json.loads(result.stdout)
        return usb_disks_from_storage(storage["disks"], storage["partitions"])
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or "").strip() or str(error)
        raise RuntimeError(f"Windows storage query failed: {detail}") from error
    except (OSError, subprocess.TimeoutExpired, ValueError, KeyError, TypeError) as error:
        raise RuntimeError(f"Cannot read Windows storage metadata: {error}") from error


def usb_changes(previous, current):
    """Return one removal or insertion per device missing from the other scan."""
    return (
        [("removed", previous[device]) for device in sorted(previous.keys() - current.keys())]
        + [("inserted", current[device]) for device in sorted(current.keys() - previous.keys())]
    )


def _usb_volume_keys(snapshot):
    volumes = {}
    for device, disk in snapshot.items():
        # The listing adapter may fall back to a disk number, which Windows can reuse.
        if not device or device.startswith("disk:"):
            raise ValueError("USB snapshot requires a physical device identity")
        for letter in disk.drive_letters:
            if not re.fullmatch(r"[A-Za-z]", letter):
                raise ValueError(f"Invalid USB drive letter: {letter!r}")
            letter = letter.upper()
            if volumes.setdefault(letter, device) != device:
                raise ValueError(f"USB snapshot has multiple owners for {letter}:")
    return {(device, letter) for letter, device in volumes.items()}


class UsbWatcherManager:
    """Drive synthetic volume watchers from snapshots keyed like scan_windows_usb().

    The required factory receives (device_id, drive_letter) and returns a watcher
    with poll(). The caller supplies the isolated test roots.
    """

    def __init__(self, snapshot_provider, watcher_factory):
        self._snapshot_provider = snapshot_provider
        self._watcher_factory = watcher_factory
        self._watchers = {}
        self._reported_volumes = set()

    def tick(self):
        """Poll current watchers and return (event, device_id, drive_letter) tuples.

        Snapshot errors propagate before any watcher is changed or polled.
        Events describe the net change since the last successful tick.
        """
        current = _usb_volume_keys(self._snapshot_provider())
        for volume in sorted(self._watchers.keys() - current):
            del self._watchers[volume]
        new_watchers = {
            volume: self._watcher_factory(*volume)
            for volume in sorted(current - self._watchers.keys())
        }
        self._watchers.update(new_watchers)

        failures = []
        for volume in sorted(current):
            try:
                self._watchers[volume].poll()
            except Exception as error:
                failures.append((volume, error))
        if len(failures) == 1:
            raise failures[0][1]
        if failures:
            details = ", ".join(
                f"{device} {letter}: {type(error).__name__}: {error}"
                for (device, letter), error in failures
            )
            raise RuntimeError(f"Multiple USB watcher polls failed ({details})") from failures[0][1]

        removed = sorted(self._reported_volumes - current)
        added = sorted(current - self._reported_volumes)
        self._reported_volumes = current
        return [("removed", *volume) for volume in removed] + [
            ("inserted", *volume) for volume in added
        ]


def list_usb():
    disks = scan_windows_usb()
    if not disks:
        print("No USB data disks with assigned drive letters found.")
        return
    for disk in sorted(disks.values(), key=lambda disk: disk.number):
        drives = ", ".join(f"{letter}:" for letter in disk.drive_letters)
        print(f"Disk {disk.number} (USB): {drives}")


def signature(path):
    info = path.lstat()
    if stat.S_ISREG(info.st_mode):
        return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


class FolderWatcher:
    """Poll direct children in an isolated test directory with fixed policies."""

    def __init__(self, directory, policies, record):
        self.directory = Path(directory)
        self.status = get_exit_point_status(policies, "USB")
        self.record = record
        self.handled = self.snapshot()
        self.previous = dict(self.handled)

    def snapshot(self):
        files = {}
        for path in self.directory.iterdir():
            try:
                version = signature(path)
            except FileNotFoundError:
                continue
            if version is not None:
                files[path] = version
        return files

    def poll(self):
        current = self.snapshot()
        for path, version in current.items():
            if self.previous.get(path) != version or self.handled.get(path) == version:
                continue
            result = inspect_file(path, self.status, destination=str(self.directory))
            try:
                if signature(path) != version:
                    continue
                if result["verdict"] == "BLOCK":
                    path.unlink()
                    action = "BLOCKED_DELETE"
                elif result["verdict"] == "LOG":
                    action = "LOGGED"
                else:
                    self.handled[path] = version
                    continue
            except FileNotFoundError:
                continue
            except OSError as error:
                self.record({**result, "action_taken": "ENFORCEMENT_ERROR", "error": str(error)})
                continue
            self.record({**result, "action_taken": action})
            self.handled[path] = version
        self.handled = {p: v for p, v in self.handled.items() if p in current}
        self.previous = current


def demo():
    policies = []
    for pid, marker, action in [(11, "ALPHA", "BLOCK"), (22, "BETA", "REPORT_ONLY")]:
        policies.append({
            "policy_id": pid, "action": action, "exit_points": ["USB"],
            "content_rules": [{"id": pid, "rule_name": marker, "rule_type": "REGEX",
                               "pattern": marker, "severity": "HIGH", "category": "INTERNAL_DOC"}],
        })
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        events = []
        watcher = FolderWatcher(root, policies, events.append)
        for name, content in [("clean.txt", "hello"), ("monitor.txt", "BETA"), ("blocked.txt", "ALPHA")]:
            (root / name).write_text(content, encoding="utf-8")
        for _ in range(4):
            watcher.poll()
        actual = sorted((Path(e["file_path"]).name, e["action_taken"], e["policy_id"]) for e in events)
        remaining = sorted(p.name for p in root.iterdir())
        if actual != [("blocked.txt", "BLOCKED_DELETE", 11), ("monitor.txt", "LOGGED", 22)] or remaining != ["clean.txt", "monitor.txt"]:
            raise RuntimeError(f"Unexpected demo outcome: {actual}, {remaining}")
        print(json.dumps({"events": actual, "remaining": remaining}, indent=2))
        print("PASS: ALLOW, LOG and post-copy BLOCK")


def server_demo(config_path):
    """Run sample copies under this device's actual USB policies and submit reports."""
    from policy_client import PolicyClient

    cfg = configparser.ConfigParser(interpolation=None)
    with open(config_path, encoding="utf-8-sig") as stream:
        cfg.read_file(stream)
    agent = cfg["agent"]
    client = PolicyClient(agent["server_url"], agent["hostname"], agent["api_token"])
    response = client.get_policy()
    if not response or not isinstance(response.get("applicable_policies"), list):
        raise RuntimeError("Cannot load assigned policies")
    policies = response["applicable_policies"]
    if not get_exit_point_status(policies, "USB")["is_governed"]:
        raise RuntimeError("This device has no assigned USB policy")

    with tempfile.TemporaryDirectory() as directory:
        def report(event):
            if event["action_taken"] == "ENFORCEMENT_ERROR":
                raise RuntimeError(event["error"])
            payload = {
                **to_report_fields(event),
                "hostname": client.hostname,
                "exit_point_type": "USB",
                "policy_id": event["policy_id"],
                "action_taken": event["action_taken"],
                "occurred_at": datetime.now(timezone.utc).isoformat(),
                "destination_value": "USB folder simulation",
            }
            if not client.send_report(payload):
                raise RuntimeError("USB demo report was not acknowledged")
            print("Server acknowledged:", event["action_taken"], event["file_path"])

        root = Path(directory)
        watcher = FolderWatcher(root, policies, report)
        for name, content in [("clean.txt", "hello"), ("monitor.txt", "BETA"), ("blocked.txt", "ALPHA")]:
            (root / name).write_text(content, encoding="utf-8")
        for _ in range(4):
            watcher.poll()
        print("Remaining:", sorted(p.name for p in root.iterdir()))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--demo", action="store_true", help="Run the isolated folder simulation")
    mode.add_argument("--list-usb", action="store_true", help="List Windows USB data disks with drive letters")
    parser.add_argument("--config", help="Use a registered device config and send real demo reports")
    args = parser.parse_args(argv)
    if args.list_usb:
        if args.config is not None:
            parser.error("--config requires --demo")
        try:
            list_usb()
        except RuntimeError as error:
            parser.exit(1, f"{error}\n")
    elif args.config:
        server_demo(args.config)
    else:
        demo()


if __name__ == "__main__":
    main()
