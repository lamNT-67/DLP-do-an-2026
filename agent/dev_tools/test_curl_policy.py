"""Regression tests for the curl watcher's policy refresh and API configuration."""

from io import StringIO
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import curl_agent as curl


def _policy():
    return {
        "policy_id": 7, "name": "Synthetic policy", "action": "BLOCK",
        "exit_points": ["CLIENT_CURL"], "allowed_files": ["public.txt"], "allowed_locations": [],
        "file_types": [{"id": 2, "extension": "txt", "category": "DOCUMENT",
                        "always_block_regardless_content": False}],
        "content_rules": [{"id": 3, "rule_name": "Synthetic rule", "rule_type": "REGEX",
                           "pattern": "DLP_TEST_MARKER", "category": "INTERNAL_DOC", "severity": "HIGH"}],
    }


class CurlPolicyTests(unittest.TestCase):
    def setUp(self):
        self.client = Mock()
        self.policy = curl.CurlPolicy(self.client)

    def _activate(self):
        self.client.get_policy.return_value = {"applicable_policies": [_policy()]}
        self.policy.refresh()
        self.assertEqual(self.policy.status["effective_action"], "BLOCK")
        return self.policy.status

    def _assert_rejected(self, responses):
        previous = self._activate()
        for response in responses:
            with self.subTest(response=response), patch("sys.stderr", new_callable=StringIO) as stderr:
                self.client.get_policy.return_value = response
                self.policy.refresh()
                self.assertIs(self.policy.status, previous)
                self.assertIn("Keeping the last valid policy snapshot", stderr.getvalue())

    def test_startup_stays_inactive_until_good_response(self):
        self.client.get_policy.return_value = None
        with patch("sys.stderr", new_callable=StringIO) as stderr:
            self.policy.refresh()
        self.assertFalse(self.policy.status["is_governed"])
        self.assertIn("inactive until the first valid policy response", stderr.getvalue())
        self._activate()

    def test_rejects_malformed_envelopes_and_partial_snapshots(self):
        self._assert_rejected([
            None, [], {}, {"applicable_policies": None}, {"applicable_policies": {}},
            {"applicable_policies": [_policy(), {}]}, {"applicable_policies": [None]},
            {"applicable_policies": [_policy(), _policy()]},
        ])

    def test_rejects_missing_fields_and_invalid_ids_or_actions(self):
        records = []
        for field in _policy():
            record = _policy()
            del record[field]
            records.append(record)
        records.extend(dict(_policy(), policy_id=value) for value in (False, -1, 0, "7", 7.0, [], 2**31))
        records.extend(dict(_policy(), action=value) for value in ("ALLOW", "BLOCKED_KILL", None, []))
        self._assert_rejected([{"applicable_policies": [record]} for record in records])

    def test_rejects_malformed_nested_policy_fields(self):
        self._assert_rejected([
            {"applicable_policies": [dict(_policy(), **{field: value})]}
            for field, value in [
                ("exit_points", "CLIENT_CURL"), ("exit_points", [1]), ("exit_points", []),
                ("allowed_files", [{"path": "public.txt"}]), ("allowed_locations", None),
                ("file_types", [None]), ("file_types", [dict(_policy()["file_types"][0], id=True)]),
                ("file_types", [dict(_policy()["file_types"][0], id=str(2**31))]),
                ("file_types", [dict(_policy()["file_types"][0], always_block_regardless_content=1)]),
                ("file_types", [dict(_policy()["file_types"][0], extension=[])]),
                ("content_rules", [None]), ("content_rules", [dict(_policy()["content_rules"][0], id=" 3")]),
                ("content_rules", [dict(_policy()["content_rules"][0], pattern=[])]),
                ("content_rules", [dict(_policy()["content_rules"][0], rule_type="UNSUPPORTED")]),
                ("content_rules", [dict(_policy()["content_rules"][0], severity={})]),
            ]
        ])

    def test_valid_explicit_empty_and_other_channel_policy_clear_curl(self):
        for rows in ([], [dict(_policy(), exit_points=["USB"])]):
            self._activate()
            self.client.get_policy.return_value = {"applicable_policies": rows}
            self.policy.refresh()
            self.assertFalse(self.policy.status["is_governed"])
            self.assertEqual(self.policy.status["effective_action"], "OPEN")

    def test_normalizes_nested_pdo_ids_and_detaches_snapshot_from_response(self):
        record = _policy()
        record["file_types"][0]["id"] = "2"
        record["content_rules"][0]["id"] = "3"
        self.client.get_policy.return_value = {"applicable_policies": [record]}
        self.policy.refresh()
        record["allowed_files"].append("private.txt")
        record["content_rules"][0]["pattern"] = "changed"
        self.assertEqual(self.policy.status["allowed_files"], ["public.txt"])
        self.assertEqual(self.policy.status["file_types"][0]["id"], 2)
        self.assertEqual(self.policy.status["content_rules"][0]["id"], 3)
        self.assertEqual(self.policy.status["content_rules"][0]["pattern"], "DLP_TEST_MARKER")

    def test_refresh_loop_recovers_after_transport_and_validation_exceptions(self):
        previous = self._activate()
        self.client.get_policy.side_effect = [
            RuntimeError("sensitive API details"), {"applicable_policies": [{}]},
            {"applicable_policies": [dict(_policy(), action="REPORT_ONLY")]},
        ]
        stop = Mock()
        stop.is_set.side_effect = [False, False, False, True]
        snapshots = []
        stop.wait.side_effect = lambda _: snapshots.append(self.policy.status)
        with patch("sys.stderr", new_callable=StringIO) as stderr:
            self.policy.run(stop)
        self.assertEqual(stop.wait.call_count, 3)
        self.assertIs(snapshots[0], previous)
        self.assertIs(snapshots[1], previous)
        self.assertEqual(self.policy.status["effective_action"], "REPORT_ONLY")
        self.assertNotIn("sensitive API details", stderr.getvalue())

    def test_refresh_continues_when_error_output_fails(self):
        self.client.get_policy.side_effect = [None, {"applicable_policies": [_policy()]}]
        stderr = Mock()
        stderr.write.side_effect = OSError("Error output unavailable")
        stop = Mock()
        stop.is_set.side_effect = [False, False, True]
        with patch("sys.stderr", stderr):
            self.policy.run(stop)
        self.assertEqual(self.policy.status["effective_action"], "BLOCK")


class CurlAPIConfigurationTests(unittest.TestCase):
    def test_rejects_unsafe_api_urls_with_generic_errors(self):
        for url in [
            "https://user:sensitive@example.test/api", "https://@example.test/api",
            "http://example.test/api?token=sensitive", "http://example.test/api#sensitive",
            "https://example.test/api?", "service.example/api", "http://example.test:65536/api",
            "http://exa\nmple.test/api",
        ]:
            with self.subTest(url=url), self.assertRaisesRegex(ValueError, "^Use an HTTP"):
                curl.CurlPolicyClient(url, "LAB", "token")

    def test_policy_transport_advances_only_on_200_and_avoids_logging_url(self):
        api = curl.CurlPolicyClient("https://example.test/sensitive-path/api/", "LAB", "secret-token")
        manager = curl.CurlPolicy(api)
        ok = Mock(status_code=200)
        ok.json.return_value = {"applicable_policies": [_policy()]}
        denied = Mock(status_code=401)
        with patch.object(curl.requests, "get", side_effect=[
            ok, denied, curl.requests.HTTPError("https://example.test/sensitive-path/api"),
        ]) as get, patch("sys.stderr", new_callable=StringIO) as stderr:
            manager.refresh()
            self.assertEqual(manager.status["effective_action"], "BLOCK")
            previous = manager.status
            manager.refresh()
            manager.refresh()
        denied.json.assert_not_called()
        self.assertIs(manager.status, previous)
        self.assertEqual(get.call_args.args, ("https://example.test/sensitive-path/api/agent_policy.php",))
        self.assertEqual(get.call_args.kwargs["headers"], {"Authorization": "Bearer secret-token"})
        self.assertNotIn("sensitive-path", stderr.getvalue())
        self.assertNotIn("secret-token", stderr.getvalue())

    def test_hostname_validation_uses_strict_utf8_and_the_api_byte_budget(self):
        self.assertTrue(curl._valid_hostname("á" * 50))
        self.assertFalse(curl._valid_hostname("á" * 51))
        self.assertFalse(curl._valid_hostname("\t \0\v"))
        self.assertFalse(curl._valid_hostname("\ud800"))

    def test_invalid_configuration_suppresses_raw_file_and_url_details(self):
        samples = [
            "[agent]\nhostname = LAB\napi_token = private-token\nserver_url = https://a.test/?token=private-url\n",
            "[agent]\nhttps://a.test/?token=private-url\nprivate-token\n",
            "[agent]\napi_token = private-token\nserver_url = https://a.test/private-url\nhostname = " + "á" * 51,
        ]
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / "config.ini"
            for sample in samples:
                config.write_text(sample, encoding="utf-8")
                with patch.object(curl.sys, "platform", "win32"), \
                        patch("sys.stderr", new_callable=StringIO) as stderr, \
                        self.assertRaises(SystemExit):
                    curl.main(["--config", str(config)])
                self.assertNotIn("private-url", stderr.getvalue())
                self.assertNotIn("private-token", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
