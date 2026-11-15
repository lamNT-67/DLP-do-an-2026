# DLP Browser Extension for Python Agent (experiment)

**Branch:** `agent-test`. This directory is deliberately at the repository root, **not** in `agent-v2/`. Nothing here is automatically installed on `main`.

Compatible with Chrome / Microsoft Edge (Manifest V3). It uses the **Python Agent on `main`**, not the .NET Agent V2. It performs best-effort checks for file picker, file drop and pasted File objects. It is not a comprehensive HTTPS/file upload security boundary: MAIN-world JS, direct network requests, service workers, browser-internal pages, untrusted synthetic events, large files and other bypasses remain limitations.

## Run locally on a Windows test VM

1. Install and register the Python Agent from `main` as normal. Ensure `C:\DLP\agent\config.ini` has the registered `api_token`, and `content_inspection.py`, `policy_utils.py` and `policy_client.py` exist.
2. Copy **this entire `extension` directory** to the test VM, e.g. `C:\DLP\extension`.
3. In PowerShell on the Windows test VM, start the bridge in a separate console:
   ```powershell
   C:\DLP\venv\Scripts\python.exe C:\DLP\extension\bridge.py --agent-dir C:\DLP\agent
   ```
   Verify:
   ```powershell
   Invoke-RestMethod http://127.0.0.1:18765/health
   ```
4. Chrome: `chrome://extensions` → Developer mode → Load unpacked → choose `C:\DLP\extension`. Edge: `edge://extensions` → Developer mode → Load unpacked.
5. On DLP Server, create/activate a `BLOCK` policy targeting **this Agent** with `BROWSER_CHROME` and/or `BROWSER_EDGE`, selected file types, and content rules. Test with small lab files (<2 MiB) on a basic HTML file upload form.
6. Confirm a new `BLOCKED_BROWSER` or `LOGGED` event in DLP Server → Logs; Wazuh receives it via the existing **Server-side** forwarder if configured.

The bridge pulls policy from DLP Server every ~20 seconds using the Python Agent's existing registration token. If the policy is unavailable it refuses uploads while testing (fail-closed); if there is **no applicable browser policy**, it allows uploads. Every selected file is inspected with the Python Content Inspection Engine using the specific matching policy; a `BLOCK` policy with no content rule may block every file in its file-type scope, consistent with the existing engine.

**No automatic Windows service installation:** run the bridge manually for this experiment. Exit the bridge process or disable the browser extension when testing is finished. Port 18765 must not already be occupied by Agent V2.

### Bridge API

- `GET http://127.0.0.1:18765/health`: readiness check.
- `POST /inspect-content`: browser extension submits `channel`, `file_name`, base64 file data and page origin. Returns `ALLOW`, `BLOCK` or `REPORT_ONLY`.
- The bridge reports events via the Python Agent `policy_client.send_report` to DLP Server `agent_report.php`. It does not contact Wazuh directly.

### Known limitations

- No Firefox support in this package; extension was built for Chrome/Edge only.
- No guaranteed intercept of direct `fetch`, XHR, encoded body uploads, file picker APIs beyond DOM events, or service workers. Replaying approved input/drop events synthetically might fail on some sites.
- 2 MiB file size limit; larger files are denied locally, **without a Server-side blocked event** because bytes are not sent for inspection.
- Localhost/header checks are not strong authentication. Use only in a trusted lab and do not expose the HTTP port off-loopback.
- A successful TCP/HTTP report does not establish that the actual remote upload was blocked in every application.
