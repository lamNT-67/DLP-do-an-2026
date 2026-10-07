import json
import os
import datetime
from pathlib import Path

LOG_DIR = Path(os.environ.get("DLP_LOG_DIR", "./logs"))
LOG_FILE = LOG_DIR / "dlp_events.log"


def _now_iso():
    return datetime.datetime.now().astimezone().isoformat()


def write_log_event(hostname, agent_module, exit_point_type, event_type, policy_state,
                     source, target, content_inspection, action_taken, reported_to_server):
    event = {
        "timestamp": _now_iso(), "hostname": hostname, "agent_module": agent_module,
        "exit_point_type": exit_point_type, "event_type": event_type,
        "policy_state": policy_state, "source": source, "target": target,
        "content_inspection": content_inspection, "action_taken": action_taken,
        "reported_to_server": reported_to_server,
    }
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")
    return event
