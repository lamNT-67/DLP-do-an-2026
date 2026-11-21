"""List or observe Windows USB volumes, or run the isolated folder simulation."""
import argparse
import configparser
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import partial
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
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
MAX_OBSERVATION_ITERATIONS = 60
MAX_OBSERVATION_INTERVAL = 60


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
    """Drive volume watchers from snapshots keyed like scan_windows_usb().

    The required factory receives (device_id, drive_letter) and returns a watcher
    with poll(). Real storage snapshots use inert watchers.
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


class _ObservationWatcher:
    def poll(self):
        """Track volume presence only, without accessing the volume."""


def observe_usb(iterations, interval):
    """Print volume lifecycle events from a bounded series of metadata scans."""
    manager = UsbWatcherManager(scan_windows_usb, lambda _device, _letter: _ObservationWatcher())
    for iteration in range(iterations):
        if iteration and interval:
            time.sleep(interval)
        for event, _, letter in manager.tick():
            print(f"{event} {letter}:", flush=True)


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


_DRY_RUN_ACTIONS = {"ALLOW": "ALLOW", "LOG": "LOGGED", "BLOCK": "WOULD_BLOCK"}


def _dry_run_filesystem():
    if sys.platform != "win32":
        raise ValueError("USB dry-run requires Windows handle-relative filesystem access")
    import _windows_dry_run
    return _windows_dry_run


class DryRunFolderWatcher:
    """Return local inspection events from a trusted synthetic scratch directory.

    The caller supplies an owned fixture on a local NTFS volume. Windows handles
    bind enumeration to that directory and content reads to validated files.
    Existing files form the baseline. Each poll checks direct children only.
    Root scan failures propagate to the caller. Failed or over-limit scans
    reset stability tracking and retain the reported history.
    Call close() when finished to release the fixture's identity pin.
    """

    def __init__(self, directory, policies, *, max_files=1024, _expected_identity=None):
        if not isinstance(max_files, int) or max_files < 1:
            raise ValueError("max_files must be a positive integer")
        self.directory = Path(os.path.abspath(directory))
        temp_root = Path(os.path.abspath(tempfile.gettempdir()))
        if self.directory == temp_root or not self.directory.is_relative_to(temp_root):
            raise ValueError("Dry-run requires a synthetic directory under the system temporary directory")
        self.directory = temp_root / self.directory.relative_to(temp_root)
        self._max_files = max_files
        self._status = get_exit_point_status(policies, "USB")
        self._filesystem = _dry_run_filesystem()
        volume = self._filesystem.local_fixture_volume(self.directory.anchor)
        self._fixture = self._filesystem.FixtureRoot(self.directory, volume, _expected_identity)
        try:
            with self._fixture.scan() as scan:
                self._previous = self._snapshot(scan) or {}
            self._reported = {path: (version, False) for path, version in self._previous.items()
                              if version is not None}
        except BaseException:
            self._fixture.close()
            raise

    def close(self):
        """Release the fixture's identity pin when polling is finished."""
        self._fixture.close()

    def _snapshot(self, scan):
        current = {}
        for name in scan.names():
            path = self.directory / name
            try:
                version = scan.version(name)
            except FileNotFoundError:
                continue
            except OSError:
                # Keep the entry present, but require fresh observations before inspecting.
                current[path] = None
            else:
                if version is None:
                    continue
                current[path] = version
            if len(current) > self._max_files:
                return None
        return current

    def _inspect_version(self, scan, path, version):
        if scan.version(path.name) != version:
            return None
        result = inspect_file(path, self._status, destination=str(self.directory),
                              open_stream=partial(scan.open_version, path.name, version))
        return result if scan.version(path.name) == version else None

    def poll(self):
        try:
            with self._fixture.scan() as scan:
                return self._poll_scan(scan)
        except (OSError, ValueError):
            self._previous = {}
            raise

    def _poll_scan(self, scan):
        current = self._snapshot(scan)
        if current is None:
            self._previous = {}
            return []

        events = []
        for path, version in sorted(current.items()):
            reported = self._reported.get(path)
            if version is None or self._previous.get(path) != version or reported == (version, False):
                continue
            try:
                result = self._inspect_version(scan, path, version)
            except FileNotFoundError:
                del current[path]
                continue
            except (OSError, self._filesystem.EntryChanged):
                result = None
            if result is None:
                current[path] = None
                continue

            # Preserve the engine's unreadable verdict once, then retry the read.
            observed = (version, result["reason"] == "UNREADABLE")
            if observed != reported:
                events.append({**result, "action_taken": _DRY_RUN_ACTIONS[result["verdict"]]})
                self._reported[path] = observed

        self._reported = {path: state for path, state in self._reported.items() if path in current}
        self._previous = current
        return events


def _demo_policies():
    policies = []
    for pid, marker, action in [(11, "ALPHA", "BLOCK"), (22, "BETA", "REPORT_ONLY")]:
        policies.append({
            "policy_id": pid, "action": action, "exit_points": ["USB"],
            "content_rules": [{"id": pid, "rule_name": marker, "rule_type": "REGEX",
                               "pattern": marker, "severity": "HIGH", "category": "INTERNAL_DOC"}],
        })
    return policies


def demo():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        events = []
        watcher = FolderWatcher(root, _demo_policies(), events.append)
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


def dry_run_demo():
    """Demonstrate inspection using only internally generated synthetic files."""
    fixtures = {"clean.txt": b"hello", "monitor.txt": b"BETA", "sensitive.txt": b"ALPHA"}
    expected = [
        ("clean.txt", "ALLOW", "ALLOW", 11),
        ("monitor.txt", "LOG", "LOGGED", 22),
        ("sensitive.txt", "BLOCK", "WOULD_BLOCK", 11),
    ]

    print("USB DRY-RUN / SIMULATION")
    filesystem = _dry_run_filesystem()
    temp_root = Path(os.path.abspath(tempfile.gettempdir()))
    with filesystem.temporary_fixture(temp_root) as fixture, closing(
        DryRunFolderWatcher(fixture.path, _demo_policies(), _expected_identity=fixture.identity)
    ) as watcher:
        versions = {}
        for name, content in fixtures.items():
            version = fixture.write_new(name, content)
            if version is None:
                raise RuntimeError(f"Synthetic fixture is not a regular file: {name}")
            versions[name] = version

        if watcher.poll():
            raise RuntimeError("Files were reported before their metadata stabilized.")
        rows = [(event["file_name"], event["verdict"], event["action_taken"], event["policy_id"])
                for event in watcher.poll()]
        if rows != expected:
            raise RuntimeError(f"Unexpected inspection results: {rows}")
        for _ in range(2):
            if watcher.poll():
                raise RuntimeError("Extra polls produced unexpected events.")

        with watcher._fixture.scan() as scan:
            if set(scan.names(include_other=True)) != fixtures.keys():
                raise RuntimeError("The set of synthetic files changed.")
            for name, content in fixtures.items():
                try:
                    with scan.open_version(name, versions[name]) as stream:
                        if stream.read(len(content) + 1) != content:
                            raise filesystem.EntryChanged
                except (OSError, filesystem.EntryChanged) as error:
                    raise RuntimeError(f"Synthetic file changed: {name}") from error

    print(f"{'FILE':<16} {'VERDICT':<8} {'ACTION':<12} POLICY ID")
    for name, verdict, action, policy_id in rows:
        print(f"{name:<16} {verdict:<8} {action:<12} {policy_id}")
    print("PASS: All 3 files unchanged. No duplicate events after 2 extra polls.")


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
    mode.add_argument("--dry-run-demo", action="store_true",
                      help="Demonstrate USB inspection on internally generated files without enforcement")
    mode.add_argument("--list-usb", action="store_true", help="List Windows USB data disks with drive letters")
    mode.add_argument("--observe-usb", action="store_true",
                      help="Print volume events from bounded Windows storage scans")
    parser.add_argument("--iterations", type=int,
                        help=f"Number of observation scans (1-{MAX_OBSERVATION_ITERATIONS}, default 3)")
    parser.add_argument("--interval", type=float,
                        help=f"Seconds between observation scans (0-{MAX_OBSERVATION_INTERVAL}, default 2)")
    parser.add_argument("--config", help="Use a registered device config and send real demo reports")
    args = parser.parse_args(argv)
    if args.config is not None and not args.demo:
        parser.error("--config requires --demo")
    if not args.observe_usb and (args.iterations is not None or args.interval is not None):
        parser.error("--iterations and --interval require --observe-usb")

    if args.observe_usb:
        iterations = 3 if args.iterations is None else args.iterations
        interval = 2 if args.interval is None else args.interval
        if not 1 <= iterations <= MAX_OBSERVATION_ITERATIONS:
            parser.error(f"--iterations must be between 1 and {MAX_OBSERVATION_ITERATIONS}")
        if not 0 <= interval <= MAX_OBSERVATION_INTERVAL:
            parser.error(f"--interval must be between 0 and {MAX_OBSERVATION_INTERVAL} seconds")
        try:
            observe_usb(iterations, interval)
        except KeyboardInterrupt:
            parser.exit(130, "USB observation interrupted.\n")
        except (RuntimeError, ValueError):
            # Storage-provider diagnostics may contain physical device identifiers.
            parser.exit(1, "USB observation failed: could not read or validate Windows storage metadata.\n")
    elif args.list_usb:
        try:
            list_usb()
        except RuntimeError as error:
            parser.exit(1, f"{error}\n")
    elif args.dry_run_demo:
        try:
            dry_run_demo()
        except (OSError, RuntimeError, ValueError) as error:
            parser.exit(1, f"USB dry-run demo failed: {error}\n")
    elif args.config:
        server_demo(args.config)
    else:
        demo()


if __name__ == "__main__":
    main()
