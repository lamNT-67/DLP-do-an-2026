"""Verify Browser Agent configuration loading with and without a UTF-8 BOM."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from browser_agent import load_config


class BrowserConfigTests(unittest.TestCase):
    def assert_config_loads(self, encoding):
        hostname = "máy-thử-nghiệm"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.ini"
            path.write_text(f"[agent]\nhostname = {hostname}\n", encoding=encoding)

            config = load_config(path)

        self.assertEqual(config["agent"]["hostname"], hostname)

    def test_loads_utf8_with_bom(self):
        self.assert_config_loads("utf-8-sig")

    def test_loads_utf8_without_bom(self):
        self.assert_config_loads("utf-8")
