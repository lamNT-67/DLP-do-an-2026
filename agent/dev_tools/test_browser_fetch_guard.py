import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
import unittest


EXTENSION = Path(__file__).resolve().parents[1] / "browser_extension"


def chromium_binary():
    candidates = [os.environ.get("DLP_TEST_CHROMIUM"), shutil.which("chromium"),
                  shutil.which("google-chrome"), shutil.which("msedge")]
    for program_files in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"):
        root = os.environ.get(program_files)
        if root:
            candidates.extend((Path(root) / "Google/Chrome/Application/chrome.exe",
                               Path(root) / "Microsoft/Edge/Application/msedge.exe"))
    return next((str(path) for path in candidates if path and Path(path).is_file()), None)


class BrowserFetchGuardTests(unittest.TestCase):
    def test_fetch_guard_in_chromium(self):
        browser = chromium_binary()
        if not browser:
            self.skipTest("Chromium unavailable. Set DLP_TEST_CHROMIUM to its executable path.")

        manifest = json.loads((EXTENSION / "manifest.json").read_text(encoding="utf-8"))
        worker = (EXTENSION / manifest["background"]["service_worker"]).read_text(encoding="utf-8")
        fixture = Path(__file__).with_name("browser_fetch_guard_fixture.js").read_text(encoding="utf-8")
        scripts = ["const workerSource = " + json.dumps(worker) + ";\n" + fixture]
        for entry in manifest["content_scripts"]:
            scripts.extend((EXTENSION / name).read_text(encoding="utf-8") for name in entry["js"])
        page = '\n'.join(['<!doctype html><meta charset="utf-8"><input id="picker" type="file">',
                          '<pre id="results"></pre><img src="/wait" alt="">',
                          '<script>addEventListener("error", e => { document.querySelector("pre").textContent += e.message; });</script>',
                          *(f"<script>\n{source}\n</script>" for source in scripts)]).encode("utf-8")
        finished = threading.Event()

        class FixtureHandler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                if self.path == "/done":
                    finished.set()
                elif self.path == "/wait":
                    # Keep the load event pending until the asynchronous DOM tests finish.
                    finished.wait(15)
                elif self.path == "/":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(page)
                    return
                self.send_response(204)
                self.end_headers()

        with (ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler) as server,
              tempfile.TemporaryDirectory(prefix="dlp-fetch-test-") as directory):
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                result = subprocess.run([
                    browser, "--headless", "--no-first-run", "--no-default-browser-check",
                    "--disable-background-networking", "--disable-component-update", "--disable-sync",
                    "--disable-gpu", "--dump-dom", f"--user-data-dir={directory}",
                    f"http://127.0.0.1:{server.server_port}/",
                ], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=45)
            finally:
                finished.set()
                server.shutdown()
                thread.join()
        self.assertEqual(result.returncode, 0, result.stderr)
        match = re.search(r'<pre id="results" data-finished="true">([^<]*)</pre>', result.stdout)
        unfinished = re.search(r'<pre id="results"[^>]*>([^<]*)</pre>', result.stdout)
        self.assertIsNotNone(match, "Browser tests did not finish. " +
                             (html.unescape(unfinished.group(1)) if unfinished else result.stderr))
        cases = json.loads(html.unescape(match.group(1)))
        self.assertGreaterEqual(len(cases), 10)
        for case in cases:
            with self.subTest(case=case["name"]):
                self.assertIsNone(case.get("error"), case.get("error"))
