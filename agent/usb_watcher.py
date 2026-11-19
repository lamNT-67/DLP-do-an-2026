"""USB folder simulation. Run with --demo to exercise post-copy inspection."""
import argparse
import configparser
from datetime import datetime, timezone
import json
import stat
import tempfile
from pathlib import Path

from content_inspection import inspect_file, to_report_fields
from policy_utils import get_exit_point_status


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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--demo", required=True, action="store_true")
    parser.add_argument("--config", help="Use a registered device config and send real demo reports")
    args = parser.parse_args()
    if args.config:
        server_demo(args.config)
    else:
        demo()
