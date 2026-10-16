# HTTP file-type DLP proxy test (Windows VM / lab)

This is an **explicit HTTP/1.1 proxy** at `127.0.0.1:18766`, NOT a transparent interception driver.
It inspects multipart/form-data **HTTP** requests up to 10 MiB, extracts filenames,
and applies active `NETWORK_WEB` policies by extension. A matching BLOCK request
receives HTTP 403 **before** the upstream request is sent. The Server records
`BLOCKED_PROXY` in Logs when API reporting works.

**HTTPS is NOT inspected or passed through:** CONNECT receives HTTP 501.
Do not configure this as a system-wide proxy or use it for general browsing.
It is intended for lab requests intentionally routed through the proxy.
It does not inspect binary uploads lacking multipart filenames, chunked POSTs,
streamed uploads, browser fetch that bypasses the proxy, or all forms of HTTP upload.
These inputs may be rejected or left uninspected depending on type; do not rely
on it as production DLP. No CA certificate is installed.

## Prepare

1. From the `agent-test` branch, run
   `server/sql/migrations/add_blocked_proxy.sql` **once** against the
   existing MySQL `dlp_system` database; deploy the branch's updated
   `server/api/agent_report.php` as well.
2. Create an active policy targeting the enrolled Device or Group:
   exit point `NETWORK_WEB`, action `BLOCK`, file type `txt`.
3. Edit `C:\ProgramData\DLPAgent\agent.json` (elevated Notepad) and add
   `"http_proxy_enabled": true` (with a comma after the preceding field).
   Reinstall/build the updated Agent from `agent-test`; restart `DLPAgent`.
   Initial installations set `http_proxy_enabled` to false.
4. Verify a running listener:
   `Get-NetTCPConnection -LocalPort 18766 -State Listen`
   and that policy.json includes `NETWORK_WEB`/`txt`.

## Test

```powershell
Set-Content -Path "$env:TEMP\dlp-block.txt" -Value "DLP synthetic demo only"
Set-Content -Path "$env:TEMP\dlp-allow.jpg" -Value "placeholder test bytes"
curl.exe --noproxy "" --proxy http://127.0.0.1:18766 -i -F "file=@$env:TEMP\dlp-block.txt" http://dlptest.com/api/http-post/
curl.exe --noproxy "" --proxy http://127.0.0.1:18766 -i -F "file=@$env:TEMP\dlp-allow.jpg" http://dlptest.com/api/http-post/
```

First request should return `HTTP/1.1 403 DLP policy blocked file type`
and create `BLOCKED_PROXY` event on Server. The second is forwarded to
the destination; response depends on the destination being reachable.

For this implementation, **do not** run the HTTPS variant through the proxy:
`curl.exe --proxy http://127.0.0.1:18766 https://dlptest.com/...` returns
501 for CONNECT, regardless of the file extension. That is not a successful
file-type DLP block; it means TLS interception is not available.

If curl attempts a direct connection rather than going through the proxy,
use `-v` to verify it connects to `127.0.0.1:18766`.
No Windows global proxy settings are modified by the installer.
