"""Verify enrollment handles HTTP responses without resending the enrollment key."""

import json
import sys
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import Mock, patch

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from policy_client import PolicyClient


API = "https://approved.example.test/api"
ENROLLMENT_KEY = "synthetic-enrollment-key"
REDIRECT_URL = "https://other.example.test/enroll?key=" + ENROLLMENT_KEY


def enrollment_response(status, location=None):
    response = requests.Response()
    response.url = f"{API}/agent_register.php"
    response.status_code = status
    if location is not None:
        response.headers["Location"] = location
    response._content = b'{"api_token":"synthetic-issued-token","device_id":7}'
    response._content_consumed = True
    response.json = Mock(wraps=response.json)
    return response


def mock_http_adapter(response):
    def send(request, **options):
        response.request = request
        return response

    return patch.object(requests.adapters.HTTPAdapter, "send", side_effect=send)


class EnrollmentClientTests(unittest.TestCase):
    def test_redirects_are_rejected_without_sending_a_second_request(self):
        for status, location in [(301, REDIRECT_URL), (302, REDIRECT_URL), (303, REDIRECT_URL),
                                 (307, REDIRECT_URL), (308, REDIRECT_URL), (307, None)]:
            with self.subTest(status=status, location=location):
                client = PolicyClient(API, "LAB")
                response = enrollment_response(status, location)
                with mock_http_adapter(response) as send, redirect_stdout(StringIO()) as output:
                    self.assertIsNone(client.register(ENROLLMENT_KEY))
                send.assert_called_once()
                self.assertEqual(send.call_args.args[0].url, f"{API}/agent_register.php")
                response.json.assert_not_called()
                self.assertEqual(client.api_token, "")
                self.assertIn("Dung dia chi API truc tiep", output.getvalue())
                self.assertNotIn(ENROLLMENT_KEY, output.getvalue())
                self.assertNotIn("other.example.test", output.getvalue())

    def test_malformed_redirect_location_fails_without_printing_server_details(self):
        client = PolicyClient(API, "LAB")
        response = enrollment_response(307, REDIRECT_URL + "\xff")
        with mock_http_adapter(response) as send, redirect_stdout(StringIO()) as output:
            self.assertIsNone(client.register(ENROLLMENT_KEY))
        send.assert_called_once()
        response.json.assert_not_called()
        self.assertEqual(client.api_token, "")
        self.assertIn("Loi register", output.getvalue())
        self.assertNotIn(ENROLLMENT_KEY, output.getvalue())

    def test_direct_enrollment_installs_the_issued_token(self):
        client = PolicyClient(API + "/", "LAB")
        response = enrollment_response(201)
        with mock_http_adapter(response) as send:
            result = client.register(ENROLLMENT_KEY, os_info="Windows", username="lab-user")
        send.assert_called_once()
        request = send.call_args.args[0]
        self.assertEqual((request.method, request.url), ("POST", f"{API}/agent_register.php"))
        self.assertEqual(json.loads(request.body), {
            "hostname": "LAB", "enrollment_key": ENROLLMENT_KEY,
            "os_info": "Windows", "username": "lab-user", "agent_version": "1.0.0",
        })
        self.assertEqual(result["device_id"], 7)
        self.assertEqual(client.api_token, "synthetic-issued-token")

    def test_http_failures_preserve_diagnostics_and_suppress_server_details(self):
        for status, diagnostic in [(409, "Hostname da dang ky roi"), (403, "HTTP 403")]:
            with self.subTest(status=status):
                client = PolicyClient(API, "LAB")
                response = enrollment_response(status)
                response.reason = ENROLLMENT_KEY
                with mock_http_adapter(response), redirect_stdout(StringIO()) as output:
                    self.assertIsNone(client.register(ENROLLMENT_KEY))
                response.json.assert_not_called()
                self.assertEqual(client.api_token, "")
                self.assertIn(diagnostic, output.getvalue())
                self.assertNotIn(ENROLLMENT_KEY, output.getvalue())


if __name__ == "__main__":
    unittest.main()
