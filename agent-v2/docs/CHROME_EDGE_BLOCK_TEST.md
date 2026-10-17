# Chrome and Edge file-upload guard (User Mode lab, v0.2)

## What is enforced

The Chromium extension intercepts:
- HTML file-picker `input` and `change` events.
- Drag-and-drop and paste of File objects.
- Selected HTML form submission, `FormData.append`, `FormData.set`,
  `fetch` and `XMLHttpRequest.send` **when the request carries FormData with File objects**.
- Actions use **per-browser policy**: `BROWSER_CHROME` vs `BROWSER_EDGE`,
  plus the legacy `NETWORK_WEB` group.

A policy `BLOCK` for `.txt` can prevent ordinary browser uploads before they
reach the server, including over HTTPS, **without TLS decryption** because the
extension sees the selected File before encryption. This does not require the
explicit HTTP proxy on port 18766. The Agent's local port 18765 is only a
read-only policy bridge, not a traffic proxy.

### Limitations / security warning

This is a proof of concept, **not bypass-resistant enterprise DLP**. Chrome/Edge
extension must be installed and enabled in each relevant browser profile.
Unmanaged users can disable or uninstall it. Main-world JavaScript can be
overridden by page scripts, and the policy handoff uses page-visible events.
`fetch` bodies built as streams, serialized bytes, custom blobs, or requests
originated outside page JavaScript are not reliably attributed to a File.
Some site-specific upload flows bypass the hooks. The extension does not yet
send an upload audit event to the server. It does not inspect file contents or
perform content-based policy matching. Avoid deployment to production devices.

## Deploy

1. Deploy `server/sql/migrations/add_application_channels.sql` on existing
   MySQL and update the server PHP policy form.
2. Assign a DEVICE policy to the enrolled host; choose
   `BROWSER_CHROME` and/or `BROWSER_EDGE`, select `txt`, `BLOCK`, save.
3. Rebuild/reinstall the Agent from `agent-test`; verify:
   ```powershell
   Get-Service DLPAgent
   Invoke-RestMethod http://127.0.0.1:18765/rules | ConvertTo-Json -Depth 8
   ```
   In the output, the appropriate browser array must contain
   `extensions: ["txt"]`, `action: "BLOCK"`.
4. In Chrome: `chrome://extensions` → Developer mode → **Load unpacked**
   → select `agent-v2/browser-extension`. If already installed, press
   **Reload** on its card after updating files.
5. In Edge: `edge://extensions` → Developer mode → **Load unpacked**
   → select the same folder; reload after updating files.
6. **Disable the old Windows global manual proxy** from lab testing.
   It is not required for browser protection and breaks HTTPS in the prototype.

## Test (controlled VM)

Create two disposable files:

```powershell
"secret test" | Set-Content "$env:TEMP\secret-test.txt"
"allowed test" | Set-Content "$env:TEMP\allowed-test.jpg"
```

Open Chrome or Edge normally, navigate to `http://dlptest.com/http-post/`
or `https://dlptest.com/https-post/` and upload `secret-test.txt`.

Expected for typical native file input: selection is cleared and popup says
"DLP policy: file upload blocked". For a FormData-driven JS upload, the
form submission may be rejected with "DLP blocked file upload" before
network transmission. This is **not** a universal guarantee across all sites.

Then upload `allowed-test.jpg`: extension should not block unless another
active policy matches `jpg`. If you previously checked *all* File Types,
uncheck `jpg` and save the policy to make this a valid allow-control test.

For negative controls, uncheck `BROWSER_EDGE` while leaving
`BROWSER_CHROME`, save, refresh Agent policy and bridge, then verify the
Edge channel is empty while Chrome still has the rule.

If a matching upload succeeds, open extension Service Worker console from
the extension page and check if `lastSync` is recent; inspect the bridge.
That website's upload mechanism may bypass the prototype. Do not claim
comprehensive HTTPS block solely from an individual success.
