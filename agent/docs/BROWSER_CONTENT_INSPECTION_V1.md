# Browser Content Inspection V1 (Chrome / Edge, lab)

## Scope
The extension now submits selected file bytes to the **local Agent** at `http://127.0.0.1:18765/inspect-content`. Agent uses the shared `ContentInspectionEngine.CheckBytes` path, so **extension does not receive content-rule regexes**. File names, file bytes and content-rule verdicts stay on the same Windows machine, while BLOCK events are reported through the existing Agent -> Server channel. The Agent's server token is never sent to browser code.

This is **best-effort user-mode protection, not system-wide guaranteed blocking**. No HTTPS decryption/certificate required for the file-picker path, since the file is inspected prior to the upload request.

Supported:
- Chrome / Edge MV3 extension file picker (`input[type=file]`) with **up to 2 MiB** per file.
- Drag and drop / paste with file objects: original event is stopped, and on ALLOW an **untrusted synthetic event** is attempted. Sites requiring trusted events may not upload; do not claim reliable support.
- Existing synchronous extension-based **file type** guard still applies to FormData, fetch, XMLHttpRequest and sendBeacon.

Limitations:
- Content inspection **is not yet integrated into MAIN-world fetch/XHR hooks** for programmatically constructed files, blobs or non-file input requests.
- On ALLOW, file picker events are replayed synthetically; sites may reject synthetic `change` events, silently fail to upload, or read the file earlier in another handler. Some sites may have registered earlier capture listeners.
- Dynamic Blob uploads, workers, cross-browser injection differences, native applications, direct SCP and downloads are not controlled.
- Unknown/invalid policy, unavailable Agent, invalid file format or file larger than 2 MiB => BLOCK for the file picker integration. More than 2 MiB is not uploaded via this code path.
- The local localhost API uses **extension Origin plus a header** as a lab access check; this is not strong authentication. Do not deploy on shared or untrusted endpoints without a stronger connector authentication design.
- Rule matching supports UTF-8 text `.txt`, `.csv`, `.json`, `.log`, `.md`, `.xml`, plus existing file extension rules. Other file types without an extension rule are rejected when a content policy applies.
- Existing agent's `NETWORK_WEB` policy applies as an additional browser-wide rule. `BROWSER_CHROME` and `BROWSER_EDGE` are also honored.

## Windows test steps
1. `git checkout agent-test; git pull origin agent-test`
2. From the `agent-v2` directory:
   `dotnet publish .\DlpAgent\DlpAgent.csproj -c Release -r win-x64 --self-contained true -o C:\DLPBuild`
3. In elevated PowerShell: stop `DLPAgent`, copy published files into the service's **actual installed path**, restart `DLPAgent`. Do not simply build without updating the service.
4. In Chrome/Edge `chrome://extensions` or `edge://extensions`, enable Developer Mode and reload the unpacked `agent-v2/browser-extension` directory. Extension version should be **0.3.0**.
5. On Server, attach a `BLOCK` content rule to the assigned policy (e.g. REGEX `CONFIDENTIAL-[0-9]{4}`), select `BROWSER_CHROME` or `BROWSER_EDGE` or `NETWORK_WEB`. **Remove `.txt` from File Types** to verify content-based matching rather than extension matching.
6. Ensure `C:\ProgramData\DLPAgent\policy.json` contains rule `content_rules` and the Agent is serving `/inspection-policy` with that rule. `/inspect-content` does not support testing via plain PowerShell without an extension-origin context.
7. Create `C:\Lab\secret.txt` with `CONFIDENTIAL-1234` and `C:\Lab\public.txt` with `public notes`.
8. On an **authorized test upload page** (for example your own `upload-test.php` with a normal `<input type="file">` and POST form), choose `secret.txt`. Expected: DLP alert, input cleared, no file reaches receiver. Then choose `public.txt`. Expected: synthetic `change` event (and likely upload if site accepts it). For ordinary HTML forms, clicking Submit should upload the allowed file.
9. Inspect Chrome/Edge extension service-worker console for `[DLP]` errors. Check Agent and Server logs for BLOCKED_BROWSER. Note that a recorded Agent verdict does not by itself prove upload prevention; verify receiver logs for blocked file.

## HTTP proxy
`http_proxy_enabled` may remain false. The browser picker path uses `127.0.0.1:18765` and does not use port 18766.
