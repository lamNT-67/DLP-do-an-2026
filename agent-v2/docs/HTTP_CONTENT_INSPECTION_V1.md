# HTTP multipart Content Inspection V1 (lab-only)

This branch now connects the explicit **HTTP** proxy at `127.0.0.1:18766` to `MultipartUploadInspector`. It is **not** an HTTPS/TLS inspection proxy and does **not** monitor direct browser uploads or arbitrary FileZilla/WinSCP/SCP traffic.

## Behavior
- Requires `http_proxy_enabled: true` in `C:\ProgramData\DLPAgent\agent.json`; restart Windows service after changing it.
- Server policy must have `NETWORK_WEB` exit point. Browser-specific policy points alone do **not** select the HTTP proxy.
- Explicit proxy only; configure client to use `127.0.0.1:18766`. No automatic system-wide interception.
- For `multipart/form-data` POST/PUT/PATCH, parses boundaries and file parts **before sending anything upstream**.
- Evaluates file extension first and then, for non-matching extensions, REGEX or DICTIONARY content rules on UTF-8 plain text files: `.txt`, `.csv`, `.json`, `.log`, `.md`, `.xml`.
- A matching `BLOCK` policy returns HTTP 403 and does **not** forward the request. `REPORT_ONLY` sends a log and allows forwarding. Matching filename allowlist entries are excluded. Local path allowlists cannot be evaluated from remote multipart filenames.
- Request body cap: 10 MiB; each inspected text part cap: 2 MiB. Unsupported formats, invalid UTF-8, malformed multipart bodies and regex failures produce HTTP 422 when content inspection is required; the request is **not forwarded**.
- Reports existing `BLOCKED_PROXY` or `LOGGED` actions to `agent_report.php`, with additional `inspection_reason` and `matched_rule_ids` fields. Server may not persist the additional metadata until schema/API support is added.
- `CONNECT` and HTTPS are **not supported**: proxy intentionally returns 501 for CONNECT. No TLS interception or certificate installation.
- This is a prototype parser for small, conventional HTTP/1.1 multipart forms; no streaming, chunked requests or RFC 5987 `filename*` support. Do not expose as a production proxy or rely on it as comprehensive DLP.

## Setup
1. Pull `agent-test`, build and publish `agent-v2/DlpAgent/DlpAgent.csproj`, stop `DLPAgent`, replace the installed binary and start the service.
2. On the Server, assign a BLOCK policy to the VM, add exit point **NETWORK_WEB**, attach active Content Rule `REGEX` pattern `CONFIDENTIAL-[0-9]{4}`. For this test leave `.txt` out of File Types.
3. Ensure the Agent's `C:\ProgramData\DLPAgent\policy.json` contains that rule and that `http_proxy_enabled` is true, then restart the Agent.
4. Use an **authorized HTTP testing endpoint** outside the current loopback interface. E.g., an HTTP upload receiver on a second lab VM. Since the proxy is explicit, the target URL must be `http://...`, not `https://...`.
5. Create two local files:
   - `C:\Lab\secret.txt` containing `CONFIDENTIAL-1234`
   - `C:\Lab\public.txt` containing `Public notes`
6. Test with Windows curl (the `-x` flag selects the proxy; `--noproxy ""` overrides existing bypass configurations):

```powershell
curl.exe --noproxy "" -x http://127.0.0.1:18766 -F "file=@C:\Lab\secret.txt" http://LAB-RECEIVER-IP:8000/upload -i
curl.exe --noproxy "" -x http://127.0.0.1:18766 -F "file=@C:\Lab\public.txt" http://LAB-RECEIVER-IP:8000/upload -i
```

Expected: sensitive content => HTTP 403 **from DLP proxy**; innocuous content => proxy forwards, then the remote receiver decides its own response (e.g., 200/404/405). The latter means forwarding was attempted, not necessarily upload success.

The localhost proxy by design does not accept `http://127.0.0.1` targets. To verify that the receiver saw or did not see a request, observe the server-side request logs on the second VM.

## Limits and tests
- Tests on this branch are still **manual**; no .NET SDK or Windows VM was available during the source edit, so build/runtime behavior is unverified.
- This proxy does not protect other traffic when applications ignore its configuration.
- Multipart non-file fields are not scanned.
- File type matching bypasses content extraction, preserving existing policy behavior.
- The reporting callback logs matching policy information but does not prove transfer completion.
