"""Exercise policy decisions with synthetic files and mocked endpoint effects."""

import base64
from contextlib import ExitStack
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import browser_agent
import clipboard_agent
import content_inspection
import network_agent
import sftp_scp_agent
from policy_utils import get_exit_point_status, unconditional_block


def rule(rule_id, pattern, severity="HIGH", category="INTERNAL_DOC"):
    return {"id": rule_id, "rule_name": f"Synthetic {rule_id}", "rule_type": "REGEX",
            "pattern": pattern, "severity": severity, "category": category}


def policy(policy_id, action, *rules, **conditions):
    return {"policy_id": policy_id, "action": action, "content_rules": rules,
            "exit_points": ["USB", "CLIPBOARD", "BROWSER_CHROME", "NETWORK_WEB",
                            "NETWORK_SCP_SFTP", "NETWORK_FTP"], **conditions}


class PolicyEvaluationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "sample.txt"

    def inspect(self, text, *policies, destination=None, enforce_file_scope=False):
        self.path.write_text(text, encoding="utf-8")
        outcomes = []
        for ordered in (policies, policies[::-1]):
            result = content_inspection.inspect_file(
                self.path, get_exit_point_status(ordered, "USB"), destination=destination,
                enforce_file_scope=enforce_file_scope)
            outcomes.append(result)
        self.assertEqual(
            {key: value for key, value in outcomes[0].items() if key != "scan_ms"},
            {key: value for key, value in outcomes[1].items() if key != "scan_ms"})
        return outcomes[0]

    def assert_decision(self, result, verdict, policy_id, action, rules=()):
        self.assertEqual((result["verdict"], result["policy_id"], result["policy_action"],
                          result["matched_rule_ids"]), (verdict, policy_id, action, list(rules)))

    def test_ruleless_block_beats_out_of_scope_monitor(self):
        monitor = policy(22, "REPORT_ONLY", rule(2, "BETA"), file_types=[{"extension": "pdf"}])
        result = self.inspect("ordinary", policy(11, "BLOCK"), monitor, enforce_file_scope=True)
        self.assert_decision(result, "BLOCK", 11, "BLOCK")
        self.assertEqual(result["reason"], "EXIT_POINT_BLOCKED")

    def test_monitor_match_beats_out_of_scope_block(self):
        block = policy(11, "BLOCK", file_types=[{"extension": "pdf"}])
        result = self.inspect("BETA", block, policy(22, "REPORT_ONLY", rule(2, "BETA")),
                              enforce_file_scope=True)
        self.assert_decision(result, "LOG", 22, "REPORT_ONLY", [2])
        self.assertEqual(result["rule_details"][0]["rule_id"], 2)

    def test_scope_and_always_block_flags_belong_to_each_policy(self):
        monitor = policy(11, "REPORT_ONLY", rule(1, "BETA"),
                         file_types=[{"extension": "txt", "always_block_regardless_content": False}])
        block = policy(22, "BLOCK", rule(2, "ALPHA"),
                       file_types=[{"extension": "txt", "always_block_regardless_content": True}])
        result = self.inspect("ordinary", monitor, block)
        self.assert_decision(result, "BLOCK", 22, "BLOCK")
        self.assertEqual(result["reason"], "FILE_TYPE_BLOCKED")

    def test_renamed_executable_is_blocked_with_or_without_monitor_policy(self):
        self.path.write_bytes(b"MZ" + bytes(64))
        block = policy(11, "BLOCK", file_types=[
            {"extension": "exe", "always_block_regardless_content": True},
        ])
        monitor = policy(22, "REPORT_ONLY", rule(2, "BETA"), allowed_files=[self.path.name])
        for policies in ([block], [block, monitor], [monitor, block]):
            for enforce_scope in (False, True):
                with self.subTest(policies=policies, enforce_scope=enforce_scope):
                    status = get_exit_point_status(policies, "CLIPBOARD")
                    result = content_inspection.inspect_file(
                        self.path, status, enforce_file_scope=enforce_scope)
                    self.assert_decision(result, "BLOCK", 11, "BLOCK")
                    self.assertEqual((result["reason"], result["declared_ext"], result["real_type"]),
                                     ("FILE_TYPE_BLOCKED", "txt", "exe"))
                    self.assertTrue(result["extension_mismatch"])

    def test_always_block_type_does_not_expand_scope_for_unrelated_content(self):
        block = policy(11, "BLOCK", file_types=[
            {"extension": "exe", "always_block_regardless_content": True},
        ])
        monitor = policy(22, "REPORT_ONLY", rule(2, "BETA"), file_types=[{"extension": "pdf"}])
        result = self.inspect("ordinary text", block, monitor, enforce_file_scope=True)
        self.assert_decision(result, "ALLOW", 11, "BLOCK")
        self.assertEqual(result["reason"], "OUT_OF_SCOPE")

    def test_unreadable_file_cannot_be_verified_against_always_block_type(self):
        block = policy(11, "BLOCK", file_types=[
            {"extension": "exe", "always_block_regardless_content": True},
        ])
        status = get_exit_point_status([block], "NETWORK_SCP_SFTP")
        result = content_inspection.inspect_file(self.path, status, enforce_file_scope=True)
        self.assert_decision(result, "BLOCK", 11, "BLOCK")
        self.assertEqual(result["reason"], "UNREADABLE")

    def test_clipboard_content_scope_does_not_change_with_an_unrelated_policy(self):
        self.path.write_text("ALPHA", encoding="utf-8")
        block = policy(11, "BLOCK", rule(1, "ALPHA"), file_types=[{"extension": "pdf"}])
        monitor = policy(22, "REPORT_ONLY", rule(2, "BETA"))
        for policies in ([block], [block, monitor], [monitor, block]):
            with self.subTest(policies=policies):
                guard = clipboard_agent.ClipboardGuard("TEST", lambda: policies)
                with patch.object(guard, "_record") as record, patch.object(clipboard_agent, "_say"):
                    replace = Mock(return_value=clipboard_agent.CLIPBOARD_REPLACED)
                    self.assertTrue(guard.on_files([str(self.path)], replace=replace)[0])
                self.assertEqual(record.call_args.args[1:3],
                                 ({"policy_ids": [11], "effective_action": "BLOCK"},
                                  clipboard_agent.ACTION_BLOCK))
                self.assertEqual(record.call_args.args[-1]["matched_rule_ids"], [1])

    def test_usb_content_scope_does_not_change_with_an_unrelated_policy(self):
        block = policy(11, "BLOCK", rule(1, "ALPHA"), file_types=[{"extension": "pdf"}])
        monitor = policy(22, "REPORT_ONLY", rule(2, "BETA"))
        for policies in ([block], [block, monitor]):
            result = self.inspect("ALPHA", *policies)
            self.assert_decision(result, "BLOCK", 11, "BLOCK", [1])
            self.assertEqual(result["reason"], "CONTENT_MATCH")

    def test_screen_capture_reports_blocking_policy_in_either_order(self):
        monitor = policy(11, "REPORT_ONLY", exit_points=["SCREEN_CAPTURE"])
        block = policy(22, "BLOCK", rule(2, "BETA"), exit_points=["SCREEN_CAPTURE"])

        def inline_thread(target, args=(), daemon=True):
            return Mock(start=lambda: target(*args))

        for policies in ([monitor, block], [block, monitor]):
            with self.subTest(policies=policies):
                reporter = Mock(return_value=12)
                guard = clipboard_agent.ClipboardGuard("TEST", lambda: policies, reporter)
                with patch.object(clipboard_agent.threading, "Thread", side_effect=inline_thread), \
                        patch.object(clipboard_agent, "write_log_event"), \
                        patch.object(clipboard_agent, "write_clipboard_delivery_status"), \
                        patch.object(clipboard_agent, "_say"):
                    replace = Mock(return_value=clipboard_agent.CLIPBOARD_REPLACED)
                    self.assertTrue(guard.on_image(replace=replace)[0])
                    self.assertTrue(guard.on_screenshot_hotkey("PrtSc"))
                self.assertEqual(reporter.call_count, 2)
                for call in reporter.call_args_list:
                    report = call.args[0]
                    self.assertEqual((report["exit_point_type"], report["policy_id"],
                                      report["action_taken"], report["matched_rule_ids"]),
                                     ("SCREEN_CAPTURE", 22, clipboard_agent.ACTION_BLOCK, []))
                self.assertEqual(reporter.call_args_list[0].args[0]["enforcement_result"], "REPLACED")
                self.assertNotIn("enforcement_result", reporter.call_args_list[1].args[0])

    def test_file_and_location_exceptions_only_exempt_their_owner(self):
        for conditions in ({"allowed_files": [self.path.name]},
                           {"allowed_locations": ["test.example:22"]}):
            with self.subTest(conditions=conditions):
                monitor = policy(11, "REPORT_ONLY", **conditions)
                block = policy(22, "BLOCK", rule(2, "ALPHA"))
                result = self.inspect("ALPHA", monitor, block, destination="test.example:22")
                self.assert_decision(result, "BLOCK", 22, "BLOCK", [2])
                exempt_block = policy(22, "BLOCK", rule(2, "ALPHA"), **conditions)
                result = self.inspect("ALPHA", exempt_block, policy(11, "REPORT_ONLY", rule(1, "ALPHA")),
                                      destination="test.example:22")
                self.assert_decision(result, "LOG", 11, "REPORT_ONLY", [1])

    def test_confidence_scores_are_policy_local(self):
        block = policy(11, "BLOCK", rule(1, "ALPHA", severity="MEDIUM"))
        monitor = policy(22, "REPORT_ONLY", rule(2, "BETA", severity="MEDIUM", category="FINANCE"))
        result = self.inspect("ALPHA BETA", block, monitor)
        self.assert_decision(result, "LOG", 11, "BLOCK", [1])
        self.assertEqual(result["confidence_level"], "LOW")

    def test_clipboard_reports_monitor_policy_and_its_rules(self):
        policies = [policy(11, "BLOCK", rule(1, "ALPHA")), policy(22, "REPORT_ONLY", rule(2, "BETA"))]
        guard = clipboard_agent.ClipboardGuard("TEST", lambda: policies)
        self.path.write_text("BETA", encoding="utf-8")
        with patch.object(guard, "_record") as record, patch.object(clipboard_agent, "_say"):
            self.assertFalse(guard.on_text("BETA")[0])
            self.assertFalse(guard.on_files([str(self.path)])[0])
        for event in record.call_args_list:
            self.assertEqual(event.args[1:3], ({"policy_ids": [22], "effective_action": "REPORT_ONLY"},
                                              "LOGGED"))
            self.assertEqual(event.args[-1]["matched_rule_ids"], [2])
        self.assertEqual(record.call_count, 2)

    def test_browser_uses_original_basename_and_reports_responsible_policy(self):
        policies = [policy(11, "BLOCK", allowed_files=["public.txt"]),
                    policy(22, "REPORT_ONLY", rule(2, "BETA"))]
        guard = browser_agent.BrowserGuard(None, "TEST")
        guard.set_policies(policies)
        body = {"channel": "chrome", "file_name": "public.txt",
                "content_base64": base64.b64encode(b"BETA").decode("ascii")}
        with patch.object(browser_agent, "_peer_process", return_value=(None, None, None)), \
                patch.object(browser_agent.threading, "Thread") as thread:
            code, result = guard.inspect(body, "https://test.example", 0)
        self.assertEqual((code, result["decision"]), (200, "REPORT_ONLY"))
        _, status, inspection, action, *_ = thread.call_args.kwargs["args"]
        self.assertEqual((status["policy_ids"], status["effective_action"], action),
                         ([22], "REPORT_ONLY", "LOGGED"))
        self.assertEqual((inspection["file_name"], inspection["matched_rule_ids"]), ("public.txt", [2]))

    def test_partial_no_match_preserves_channel_decisions(self):
        policies = [policy(11, "BLOCK", rule(1, "blue"))]
        self.path.write_text("ordinary", encoding="utf-8")
        browser = browser_agent.BrowserGuard(None, "TEST")
        browser.set_policies(policies)
        body = {"channel": "chrome", "file_name": self.path.name,
                "content_base64": base64.b64encode(self.path.read_bytes()).decode("ascii")}
        clipboard = clipboard_agent.ClipboardGuard("TEST", lambda: policies)
        with patch.object(content_inspection, "MAX_TEXT_CHARS", 3), patch.object(clipboard, "_record") as record:
            code, result = browser.inspect(body, "https://test.example", 0)
            self.assertEqual((code, result["decision"], result["reason"]), (200, "ALLOW", "INSPECTION_INCOMPLETE"))
            self.assertEqual(clipboard.on_text("ordinary"), (False, None))
            record.assert_not_called()
            status = get_exit_point_status(policies, "NETWORK_SCP_SFTP")
            self.assertIsNone(sftp_scp_agent._inspect_file(str(self.path), status))
            status = get_exit_point_status(policies, "NETWORK_WEB")
            network = network_agent._inspect_blacklist_match("ordinary", status)
            self.assertEqual((network["verdict"], network["inspection_coverage"]), ("ALLOW", "PARTIAL"))

    def test_browser_and_transfer_keep_declared_extension_scope(self):
        block = policy(11, "BLOCK", rule(1, "ALPHA"), file_types=[{"extension": "pdf"}])
        monitor = policy(22, "REPORT_ONLY", rule(2, "BETA"))
        self.path.write_text("ALPHA", encoding="utf-8")
        guard = browser_agent.BrowserGuard(None, "TEST")
        body = {"channel": "chrome", "file_name": self.path.name,
                "content_base64": base64.b64encode(b"ALPHA").decode("ascii")}
        for policies in ([block], [block, monitor], [monitor, block]):
            with self.subTest(policies=policies):
                guard.set_policies(policies)
                with patch.object(browser_agent, "_peer_process") as peer:
                    code, result = guard.inspect(body, "https://test.example", 0)
                peer.assert_not_called()
                self.assertEqual((code, result["decision"]), (200, "ALLOW"))
                for channel in ("NETWORK_SCP_SFTP", "NETWORK_FTP"):
                    status = get_exit_point_status(policies, channel)
                    self.assertIsNone(sftp_scp_agent._inspect_file(str(self.path), status))

    def test_page_fetch_destination_hint_is_reporting_only(self):
        guard = browser_agent.BrowserGuard(None, "TEST")
        destination = "https://receiver.example"
        guard.set_policies([policy(4, "BLOCK", rule(5, "Confidential"), allowed_locations=[destination])])
        body = {"channel": "chrome", "file_name": "sample.txt",
                "content_base64": base64.b64encode(b"Confidential").decode("ascii")}
        _, picker = guard.inspect(body, destination, 0)
        self.assertEqual((picker["decision"], picker["reason"], picker["reusable_for_page_fetch"]),
                         ("ALLOW", "ALLOWED_LOCATION", False))

        with patch.object(browser_agent, "_peer_process", return_value=(None, None, None)), \
                patch.object(browser_agent.threading, "Thread") as thread:
            _, fetch = guard.inspect({**body, "initial_destination_hint": destination}, destination, 0)
        self.assertEqual((fetch["decision"], fetch["reason"]), ("BLOCK", "CONTENT_MATCH"))
        _, status, inspection, action, reported_dest, _ = thread.call_args.kwargs["args"]
        self.assertEqual((status["policy_ids"], inspection["matched_rule_ids"], action, reported_dest),
                         ([4], [5], "BLOCKED_BROWSER", destination))

    def test_transfer_decision_and_blanket_port_eligibility(self):
        self.path.write_text("ALPHA", encoding="utf-8")
        monitor = policy(11, "REPORT_ONLY", allowed_locations=["test.example:22"],
                         file_types=[{"extension": "pdf"}])
        block = policy(22, "BLOCK")
        for exit_point in ("NETWORK_SCP_SFTP", "NETWORK_FTP"):
            with self.subTest(exit_point=exit_point):
                status = get_exit_point_status([monitor, block], exit_point)
                result = sftp_scp_agent._inspect_file(self.path.as_posix(), status, "test.example:22")
                self.assert_decision(result, "BLOCK", 22, "BLOCK")
                self.assertEqual(unconditional_block(status, file_conditions=True)["policy_ids"], [22])
                exempt = policy(22, "BLOCK", allowed_locations=["test.example:22"])
                status = get_exit_point_status([monitor, exempt], exit_point)
                self.assertIsNone(unconditional_block(status, file_conditions=True))
                self.assertIsNone(sftp_scp_agent._inspect_file(self.path.as_posix(), status, "test.example:22"))

    def test_web_blacklist_monitor_match_does_not_trigger_block(self):
        monitor = policy(22, "REPORT_ONLY", rule(2, "BETA"))
        block = policy(11, "BLOCK", rule(1, "ALPHA"))
        for policies in ([block, monitor], [monitor, block]):
            status = get_exit_point_status(policies, "NETWORK_WEB")
            self.assert_decision(network_agent._inspect_blacklist_match("BETA", status),
                                 "LOG", 22, "REPORT_ONLY", [2])
            self.assert_decision(network_agent._inspect_blacklist_match("ALPHA BETA", status),
                                 "BLOCK", 11, "BLOCK", [1])
        status = get_exit_point_status([monitor, policy(11, "BLOCK")], "NETWORK_WEB")
        self.assertEqual(unconditional_block(status, file_conditions=False)["policy_ids"], [11])

    def test_network_loop_reports_monitor_match_without_enforcement(self):
        ip = "192.0.2.5"
        monitor = policy(22, "REPORT_ONLY", rule(2, r"192\.0\.2\.5"))
        block = policy(11, "BLOCK", rule(1, "ALPHA"))
        client = Mock()
        client.get_policy.return_value = {
            "applicable_policies": [block, monitor],
            "network_blacklist": [{"target_type": "IP", "value": ip}],
        }
        connection = Mock(raddr=Mock(ip=ip, port=443), pid=123)
        with ExitStack() as stack:
            def stub(name, **kwargs):
                return stack.enter_context(patch.object(network_agent, name, **kwargs))

            stub("load_config", return_value={"agent": {"hostname": "TEST", "firewall_drop_log": "false"}})
            stub("_ensure_registered", return_value=client)
            blocker = stub("DomainBlocker").return_value
            blocker.sync.return_value = []
            blocker.blocked_ips.return_value = set()
            stub("DropLogTailer").return_value.read_new_drops.return_value = []
            stub("_prune_reactive_rules")
            stub("_get_process_name", return_value="synthetic")
            enforce = stub("_block_connection")
            remove = stub("_remove_rules")
            log = stub("write_log_event")
            stack.enter_context(patch.object(network_agent.psutil, "net_connections", return_value=[connection]))
            stack.enter_context(patch.object(network_agent.time, "sleep", side_effect=StopIteration))
            with self.assertRaises(StopIteration):
                network_agent.run()

        blocker.sync.assert_called_once_with([], [ip], False)
        enforce.assert_not_called()
        remove.assert_not_called()
        report = client.send_report.call_args.args[0]
        self.assertEqual((report["policy_id"], report["action_taken"], report["matched_rule_ids"]),
                         (22, "LOGGED", [2]))
        self.assertEqual(log.call_args.args[4], "REPORT_ONLY")

    def test_transfer_loop_requests_blanket_and_reports_blocking_policy(self):
        self.path.write_text("ordinary", encoding="utf-8")
        monitor = policy(11, "REPORT_ONLY", rule(1, "BETA"), file_types=[{"extension": "pdf"}])
        block = policy(22, "BLOCK")
        client = Mock()
        client.get_policy.return_value = {"applicable_policies": [monitor, block]}
        proc = Mock(info={"name": "scp.exe"}, pid=123)
        with ExitStack() as stack:
            def stub(name, **kwargs):
                return stack.enter_context(patch.object(sftp_scp_agent, name, **kwargs))

            stub("load_config", return_value={"agent": {"hostname": "TEST"}})
            stub("_ensure_registered", return_value=client)
            stub("_ps")
            stub("open", create=True)
            ports = stub("_ensure_port_rules")
            stub("_find_root", return_value=proc)
            stub("_tree", return_value=[proc])
            stub("_suspend_tree")
            stub("_resume_tree")
            stub("_kill_tree")
            stub("_safe_cwd")
            stub("_files_from_cmdline", return_value=[str(self.path)])
            stub("_get_open_files", return_value=[])
            stub("_get_remote_endpoint", return_value=("192.0.2.5", 22))
            stub("_get_username", return_value="synthetic")
            enforce = stub("_block_process_and_connection", return_value="BLOCKED_KILL")
            log = stub("write_log_event")
            stack.enter_context(patch("faulthandler.cancel_dump_traceback_later"))
            stack.enter_context(patch("faulthandler.dump_traceback_later"))
            stack.enter_context(patch.object(sftp_scp_agent.psutil, "process_iter", return_value=[proc]))
            stack.enter_context(patch.object(sftp_scp_agent.time, "sleep", side_effect=StopIteration))
            with self.assertRaises(StopIteration):
                sftp_scp_agent.run()

        ports.assert_called_once_with(sftp_scp_agent.PROACTIVE_PORTS, {"NETWORK_SCP_SFTP", "NETWORK_FTP"})
        enforce.assert_called_once_with([proc], "192.0.2.5", 22)
        report = client.send_report.call_args.args[0]
        self.assertEqual((report["policy_id"], report["action_taken"], report["matched_rule_ids"]),
                         (22, "BLOCKED_KILL", []))
        self.assertEqual(log.call_args.args[4], "BLOCK")


if __name__ == "__main__":
    unittest.main()
