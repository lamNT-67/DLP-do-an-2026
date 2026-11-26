"""Entry point of the limited, interactive DLPCurlAgent task."""

import os
from pathlib import Path
import signal
import sys

from curl_desktop import private_journal_directory, session_end_notifications
from curl_lifecycle import ManagedInstance
from curl_windows import OriginUnavailable, watcher_scope


CONFIG = Path(r"C:\DLP\agent\config.ini")


def _load_watcher(directory):
    # log_writer selects its paths at import. Ignore any inherited shared DLP_LOG_DIR.
    os.environ["DLP_LOG_DIR"] = str(directory)
    import log_writer
    if (log_writer.LOG_FILE != directory / "dlp_events.log"
            or log_writer.CURL_DELIVERY_FILE != directory / "curl_delivery.log"):
        raise RuntimeError("Private Curl journals unavailable")
    from curl_agent import run_managed_watcher
    return run_managed_watcher


def run():
    scope = watcher_scope()
    with ManagedInstance(scope) as instance:
        if not instance.admitted:
            return 0
        started = False
        previous = signal.signal(signal.SIGINT, lambda *_: instance.stop.set())
        try:
            with session_end_notifications(instance.stop):
                watch = _load_watcher(private_journal_directory(scope))
                started = True
                outcome = watch(CONFIG, scope, instance.stop)
                state = instance.finish(outcome)
                if state != "complete":
                    return 2
                return int(outcome["runtime_failed"])
        except Exception:
            if not started:
                instance.finish({"pending_resumes": 0, "worker_cleanup_confirmed": True,
                                 "report_drained": True, "runtime_failed": True})
            # Once scanning begins, an unexpected failure leaves durable uncertainty.
            raise
        finally:
            signal.signal(signal.SIGINT, previous)


def main():
    try:
        return run()
    except OriginUnavailable:
        print("Curl task requires a supported limited interactive token.", file=sys.stderr)
        return 3
    except Exception:
        # Errors can contain profile paths or device configuration. The task exit
        # status and the protected instance ledger are available to the installer.
        print("Managed Curl startup or cleanup could not be confirmed.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
