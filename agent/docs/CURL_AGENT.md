# Curl Agent V1

The Windows watcher discovers native `curl.exe` processes as users run curl in their usual shell. It uses the device's existing enrollment and evaluates policies assigned to `CLIENT_CURL`. In **Policies**, activate **CLI - cURL (curl.exe)** on the enrolled device or its group.

## Managed deployment

- The Windows installer registers `\DLPCurlAgent` for limited interactive logons in the built-in Users group. Coverage starts at the next eligible sign-in. The task permits parallel sessions, while the watcher admits one instance per Windows SID, authentication LUID and session ID. It checks its actual token and the originating curl token before inspecting or controlling curl. Elevated, SYSTEM, unattended and pre-login curl remain outside managed coverage.
- The installer stages a versioned runtime and isolated virtual environment under `%ProgramFiles%\DLP-Curl`. It uses the same protected all-users base Python as the shared DLP runtime. Pass `-CurlPython "C:\Program Files\Python311\python.exe"` to `install.ps1` to select a specific machine-wide interpreter. Use the actual installed path. See [Python setup and diagnostics](INSTALLER_PYTHON.md).
- The watcher reads `C:\DLP\agent\config.ini` and uses the device token issued through the existing enrollment flow. It waits up to five minutes per startup, checking every five seconds, and the task retries failures up to three times at one-minute intervals. Maintenance interrupts the wait. Each new watcher stays inactive until it receives a valid policy snapshot.
- Setup publishes a fresh administrator-owned `C:\DLP` with read and execute access for standard users. For a recognized unsafe legacy installation, setup verifies enrollment against an independently approved server and archives the incumbent directories after cooperative Curl and shared-agent shutdown. [Migration and recovery](INSTALLER_PYTHON.md#legacy-migration-and-recovery)
- Managed journals are in `%LOCALAPPDATA%\DLP-Curl`, with access for the originating account, Administrators and SYSTEM. `DLPNotifier` reads the current account's private event journal alongside the shared journal for other modules. Each limited interactive logon gets its own notifier, with a single instance per logon. Managed Curl writes the verified session ID and logon LUID into the local event source so the matching desktop receives the alert. Processes running as the originating account can alter its journals and can already read the same device configuration. Server acknowledgements record server receipt of a report. Local journals and cleanup receipts are operational evidence within this user trust model. [Windows task instance policy](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasksettings-multipleinstances)
- Upgrade and uninstall disable new task starts and request cooperative shutdown. The installer checks task and watcher exit and looks for instance-specific cleanup evidence. It preserves the disabled task and runtime when cleanup is incomplete or unconfirmed. Receipt fields distinguish unresolved resumes, worker cleanup, report-drain timeout and runtime failure. A forced or abnormal exit can leave a running record without a terminal receipt. Scheduler status alone does not certify cleanup. Records are under the 64-bit `HKLM\SOFTWARE\DLP\ManagedCurl\Instances` key. Avoid Task Scheduler **End** for normal maintenance.
- Curl rollback can restore a prior registered generation if switching fails and withdrawal is confirmed safe. Once shared cutover has started, the recovered Curl registration stays disabled pending review. An interrupted installer can require administrator review of the protected generation record and task. Uninstall retains per-account journals and machine lifecycle evidence. `-RemoveFiles` archives the shared roots and removes validated owned Curl releases.
- If the owned task is fenced and no managed interpreter remains, setup can snapshot unresolved `running` records beside a volatile restart witness. When that witness disappears on a subsequent full Windows restart, setup can accept the exact unchanged records as abandoned. The original records stay intact. The separate administrator-owned `RestartEvidence` entries record that cleanup remains unconfirmed. An existing v1 record has no boot identity, so earlier restarts cannot qualify it before setup takes this snapshot. Same-boot retries and sleep or hibernation resume preserve the witness and keep cutover blocked. Incomplete, missing, changed, and stale receipts still fail the gate. [Windows volatile registry keys](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regcreatekeyexw)

## Standalone lab

Stop any existing standalone watcher before the first managed install. On an unmanaged endpoint run from the repository root with the Agent dependencies and an enrolled lab configuration. Stop with Ctrl+C.

```powershell
$env:DLP_LOG_DIR = Join-Path $env:LOCALAPPDATA 'DLP\logs'
python -B agent/curl_agent.py --config C:\DLP\agent\config.ini
```

Curl enforcement is inactive at startup and after a restart until the first valid policy response. The watcher refreshes policy every 60 seconds and retains the last valid snapshot in memory on request or validation failure. A valid empty applicable-policy list clears enforcement. Configure an HTTP(S) API base URL without credentials, a query, or a fragment. Use HTTPS when connecting to the lab server over a network.

## Upload syntax

Pass an explicit `http://` or `https://` URL as an operand or via `--url`. The examples use a local receiver and synthetic files.

| Option | Example |
| --- | --- |
| `-T` / `--upload-file` | `curl.exe -T '.\source file.txt' http://127.0.0.1:8765/upload` |
| `-F` / `--form` | `curl.exe -F 'file=@.\source file.txt;type=text/plain' http://127.0.0.1:8765/upload` |
| `-F` file-backed form value | `curl.exe -F 'text=<.\source file.txt' http://127.0.0.1:8765/upload` |
| `-d` / `--data` / `--data-ascii` | `curl.exe -d '@.\source file.txt' http://127.0.0.1:8765/upload` |
| `--data-binary` | `curl.exe --data-binary '@C:\Lab\source file.txt' http://127.0.0.1:8765/upload` |

The watcher reads Windows argument tokens, so shell-quoted paths can contain spaces. Relative paths use the curl process's working directory. Use repeated form or data flags for multiple files to one URL, or one `-T` operand per URL, paired in argument order. Multipart files can have simple `;type=` and `;filename=` attributes or curl-style double quotes around the path. Attached short-option values are supported. Long `--option=value` syntax requires curl 8.16.0 or later. [curl option documentation](https://curl.se/docs/manpage.html)

Ordinary GET, `-I`/`--head`, downloads, literal `--data`/`--data-binary`, `--data-raw`, and `--form-string` have no supported file body. An explicit `-X GET` or `-X HEAD` can still carry a file body. Curl uses the method supplied by `-X` as the request method string. [curl --request documentation](https://curl.se/docs/manpage.html#-X)

Coverage is limited to the explicit command line. The watcher records a local coverage event and continues execution when it encounters ambiguous or unsupported syntax. This includes config files and `--next`, redirects such as `-L`, parallel mode, URL or upload globbing, scheme guessing, stdin, UNC/device/drive-relative paths, comma-separated form attachments, advanced multipart attributes, and alternate body options such as `--json`, `--data-urlencode` and `--url-query`. File-backed `-H`/`--header` input and file data moved into a query by `-G` are also outside scope. Literal headers remain supported. The limit is 32 file operands. An unrecognized option can make the entire command ambiguous. Implicit `.curlrc` settings are outside the watcher’s visibility. The loopback procedure passes `-q` first for reproducibility.

## Enforcement and logging

- The watcher polls about every 250 ms when idle. It refreshes process identities before checking for curl and retries unavailable command lines and working directories up to three times. For a recognized file upload governed by a BLOCK policy it attempts to suspend curl, then invokes the shared inspection engine in a Python subprocess with a five-second timeout. Process startup and cleanup can extend the pause. A REPORT_ONLY policy on its own leaves the process running during inspection. File types, allowed files, allowed locations, and content rules apply independently for each policy. Destination exceptions match the URL's declared `hostname:port`, such as `upload.example.com:443` or `[::1]:8765`. The actual network peer can differ.
- The highest result across the files controls the process, in order `BLOCK > LOG > ALLOW`. The first BLOCK can interrupt all requests in the process. Coverage events identify operands that were skipped, partially inspected, unreadable, or uninspectable. The shared engine's policy dispositions still apply and are distinct from inspection coverage. A timeout can leave the batch incomplete.
- Managed inspection retains identity-verified handles for members of its private job, including nested jobs. Windows snapshots can miss short-lived members. Cleanup requires every retained handle to signal within the existing one-second deadline and checks the verified handle count against the job's lifetime process count after the waits. An incomplete snapshot, an unresolved member, or an expired wait makes cleanup unconfirmed and prevents a complete receipt. The proof covers members of this job and its nested jobs. [Windows job membership](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_process_id_list) · [Lifetime accounting](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_accounting_information)
- **Polling cannot guarantee prevention.** Curl can send headers or body bytes before suspension, and a fast process can finish between polls. Data buffered by the OS can continue to arrive after suspension. Where content is read, the watcher uses the same regular file handle for inspection and hashing. It excludes mapped network drives, reparse points, and aliases whose opened path cannot be verified. A consistent handle says which file the watcher inspected. Curl may read a different file or bytes that change over time.
- Ctrl+C stops new inspections. The watcher tries to resume any process it suspended and distinguishes an already-exited process from access denial and other OS errors. It retries failures during polling and makes up to three final attempts on shutdown. Forced termination or persistent Windows access denial can leave curl suspended. Restarting the watcher does not recover its prior suspension state.
- `dlp_events.log` records the reason, inspection coverage, policy disposition, and suspension, termination, and resume outcomes. `BLOCKED_KILL` means Windows accepted the termination request and the process handle signaled exit. A BLOCK decision with an already exited process, failed termination, or unconfirmed termination is `LOGGED`. Clean, excepted, out-of-scope, and coverage records are kept locally. Logs contain the file basename, the URL's hostname and port, and rule metadata. The raw command line, credentials, URL path and query, and content samples are omitted.
- The notifier displays confirmed `BLOCKED_KILL` violations written for its logon after startup. The message reports that Curl was stopped and shows only the basename and destination host and port if available. Each event ID is eligible once per notifier run. The reader starts at the end of the active journal and follows new complete records through journal creation, truncation and replacement. Records rotated out before a poll can be missed. Windows notification settings control whether a balloon is shown.
- For LOG and BLOCK dispositions, local journaling is attempted before the report. Join `curl_delivery.log` to `dlp_events.log` by `event_id` and check for `ACKNOWLEDGED` and a positive `server_log_id` from HTTP 201. `UNACKNOWLEDGED` covers a failed or invalid reply. `NOT_QUEUED` covers a full or closing queue. `LOCAL_EVENT_FAILED` records a local write failure and may be followed by an acknowledgment for the same ID. The watcher also prints a safe error if it cannot write the delivery journal. Oversized optional report fields are omitted or capped to the PHP API's byte limits. The local record keeps the original metadata.
- Graceful shutdown allows two seconds for queued reports to drain. A missing delivery record can indicate a pending or interrupted report. There is no automatic report replay, and an unacknowledged report may already have been stored by the server.

## Controlled HTTP receiver procedure

From the repository root, on Windows with the existing Agent dependencies, run the fixture.

```powershell
python -B agent/dev_tools/curl_receiver_test.py
```

The fixture binds only to `127.0.0.1` on an ephemeral port, disables curl proxies, creates synthetic files in a temporary directory, and watches only its own curl child processes. Its in-process HTTP stub supplies the policy and returns report log IDs. Each output line counts requests with parsed headers, declared body bytes, bytes already received before the first poll, total body bytes received, complete bodies, and the related DLP decision. Multipart counts include framing.

| Case | How to evaluate the output |
| --- | --- |
| `get`, `head`, `download`, `literal` | Expect a successful request and no DLP decision. Confirm the download file was written. |
| `clean-put`, `clean-form`, `clean-data` | Expect `ALLOW`, a resumed process, and the complete body. The multipart case reads two files. |
| `report-only` | Expect `LOGGED` with a positive stub log ID and the entire file received. |
| `blocked-before-body` | The receiver delays `100 Continue`. Compare the request count and received bytes with the confirmed termination. |
| `partial-block` | A rate-limited upload starts immediately. Compare bytes before the first poll and total bytes with the declared size. Any body bytes received demonstrate leakage. |
| `fast-block` | A small upload starts immediately. A complete body with no decision demonstrates a transfer finishing between polls. |
| `unsupported` | Expect a local coverage event and a completed request. |

The fixture checks process decisions and report acknowledgments. Its success status does not assert zero received bytes on BLOCK cases. For server verification after review, use a local PHP/MySQL lab and an enrolled device, review and apply the migration manually if needed, and check that Admin **Logs** filters the reported rows under **CLI - cURL (curl.exe)**. Match the stored log IDs with the local delivery journal and verify direct and group assignment, token rejection, and rejection of a policy ID outside the device's assignment. The loopback stub does not exercise PHP authentication or MySQL.

## DLP-LAB01 deployment and acceptance

1. Copy the working tree to a location on DLP-LAB01 readable by the lab users and use the VM's existing enrollment and accounts. Stop any standalone Curl watcher and finish any overlapping lab task run. Keep the Checkpoint 2C.1 task disabled during the test if it would otherwise launch a watcher. In an elevated 64-bit Windows PowerShell opened in the copied repository, install and inspect the task. Supply `-CurlPython` only if needed. The installer reuses the existing config.

   ```powershell
   .\agent\service\install.ps1 -NoPrompt
   $task = Get-ScheduledTask -TaskPath '\' -TaskName DLPCurlAgent
   $task.Actions
   $task.Principal
   $task.Triggers
   $task.Settings
   ```

   For a non-loopback HTTP server on the isolated lab network, add `-AllowInsecureLabServer`. An unsafe legacy installation also requires the approved `-ServerUrl` and, if it differs from the Windows machine name, `-Hostname`.

   Expect one enabled, unfiltered logon trigger, the built-in Users SID `S-1-5-32-545`, Group logon, Limited run level, the protected versioned Python action, parallel instances, unlimited run time, battery start and continuation, no idle requirement, hard termination disabled in the task, and three restarts at one-minute intervals.

2. Sign in as DLPTestA and switch to a real interactive logon as DLPTestB with A still signed in. Task Scheduler Operational history should show a logon-triggered run for each. From an elevated PowerShell with the copied repository as the current directory, read the two interpreter tokens and compare each to its session's Explorer token. Windows can show both the venv launcher and the actual interpreter. Expect one logical watcher per account. Reconnect to a session or launch the same task command from an existing standard-user shell and confirm no extra watcher stays running.

   ```powershell
   $task = Get-ScheduledTask -TaskPath '\' -TaskName DLPCurlAgent
   $ids = Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='explorer.exe'" |
       Where-Object { $_.Name -eq 'explorer.exe' -or $_.CommandLine -like '*\DLP-Curl\*\curl_managed.py*' } |
       Select-Object -ExpandProperty ProcessId
   $probe = @'
   import sys
   sys.path.insert(0, 'agent')
   from curl_windows import _api, OriginUnavailable
   api = _api()
   for pid in map(int, sys.argv[1:]):
       try:
           handle = api.open_process(pid)
           try:
               token = api.open_process_token(handle)
               try:
                   scope, _ = api.token_context(token)
                   print(pid, api.image_name(handle), scope.user_sid.hex(), hex(scope.authentication_id), scope.session_id)
               finally:
                   api.close(token)
           finally:
               api.close(handle)
       except (OSError, OriginUnavailable):
           print(pid, 'unsupported or unavailable')
   '@
   & $task.Actions.Execute -B -c $probe @ids
   ```

3. Start the existing loopback receiver from a separate PowerShell in the copied repository. Use a normal user account with the installed Curl interpreter path from step 1. The port is printed on startup. This receiver provides destination-side byte counts. Keep policy and reporting pointed at the existing lab DLP server.

   ```powershell
   $receiver = @'
   import sys
   sys.path.insert(0, 'agent/dev_tools')
   from curl_receiver_test import Handler, Receiver
   class Meter(Handler):
       def _handle(self):
           super()._handle()
           print(self.path, [(r['bytes'], r['expected']) for r in self.server.requests.get(self.path, [])], flush=True)
       do_GET = do_HEAD = do_PUT = do_POST = _handle
   with Receiver() as server:
       server.RequestHandlerClass = Meter
       print(server.server_port, flush=True)
       server.serve_forever()
   '@
   & 'C:\Program Files\DLP-Curl\GENERATION\venv\Scripts\python.exe' -B -c $receiver
   ```

   In the lab dashboard, use the existing test policy and add a synthetic marker rule only if needed. The following example uses `SYNTHETIC_CURL_DLP_TEST`. Wait for policy refresh after each dashboard change. From each test user shell, set `$port` to the printed port and run these transfers. Run the marker upload once under BLOCK and again under REPORT_ONLY.

   ```powershell
   $url = "http://127.0.0.1:$port"
   $clean = Join-Path $env:TEMP 'curl-managed-clean.txt'
   $marker = Join-Path $env:TEMP 'curl-managed-marker.txt'
   Set-Content $clean 'synthetic clean data'
   Set-Content $marker 'SYNTHETIC_CURL_DLP_TEST'
   curl.exe -q --noproxy '*' -sS --http1.1 -H 'Expect: 100-continue' -T $clean "$url/clean"
   curl.exe -q --noproxy '*' -sS --http1.1 -H 'Expect: 100-continue' -T $marker "$url/marker"
   curl.exe -q --noproxy '*' -sS -o (Join-Path $env:TEMP 'curl-managed-download.json') "$url/download"
   Get-Content (Join-Path $env:LOCALAPPDATA 'DLP-Curl\dlp_events.log') -Tail 8
   Get-Content (Join-Path $env:LOCALAPPDATA 'DLP-Curl\curl_delivery.log') -Tail 8
   ```

   Expect ALLOW and full delivery for the clean file, confirmed curl termination for the detectable BLOCK transfer, and LOGGED with full delivery for REPORT_ONLY. Record the actual bytes for all transfers. Check that GET and download complete, and exercise positive and negative Allowed Files and Allowed Locations using the same marker upload and existing lab allowlist procedure. Match LOG and BLOCK event IDs to the server log IDs. For each account, verify that the other account cannot read its journals and that the shared Notifier journal contains no managed Curl events. Cross-session transfers must create decisions only in the originating account's journal.

4. With both sessions present, run the install command again using the same lab options to test upgrade and then inspect the cleanup ledger. Expect dated Operational history for both old task runs, no running old watcher or inspection worker, and a replacement task ready for the next logon. Confirm complete receipts for the stopped instances with the same maintenance-operation ID, `pending_resumes=0` and `worker_cleanup_confirmed=true`. Record `report_drained` independently. For the in-flight stop case, repeat with synthetic uploads and confirm the maintenance request overlaps an actual watcher-owned suspension. Check that the native curl resumes or had already exited and that no worker descendant remains. Mark this case **NOT VERIFIED** if the stop window is missed. Also test a normal logoff and review the resulting local-operation receipt.

   ```powershell
   .\agent\service\install.ps1 -NoPrompt
   reg.exe query 'HKLM\SOFTWARE\DLP\ManagedCurl\Instances' /s /reg:64
   Get-ScheduledTask -TaskPath '\' -TaskName DLPCurlAgent | Get-ScheduledTaskInfo
   ```

5. After taking a VM checkpoint, exercise rollback after replacing the task with a disabled staged release. Run this in the same elevated shell and use the same trusted Python path as in step 1. Verify that the original task action and enabled state return and that the staged release is removed. Confirm that the restored generation starts on the next sign-in.

   ```powershell
   . .\agent\service\curl_task.ps1
   . .\agent\service\installer_python.ps1
   $base = Resolve-CurlPython 'C:\Program Files\Python311\python.exe'
   $deployment = Open-CurlDeployment $true
   try {
       New-CurlRelease $deployment (Resolve-Path .\agent).Path $base
       Enter-CurlMaintenance $deployment $deployment.Task
       $deployment.Switched = $true
       Register-CurlRelease $deployment $deployment.Staged $true | Out-Null
   } finally {
       try { Undo-CurlInstall $deployment } finally { Close-CurlDeployment $deployment }
   }
   ```

6. On a disposable VM checkpoint, run `.\agent\service\uninstall.ps1` with live test watchers and check that it withdraws the task after valid cleanup, with private journals retained. Exercise `-RemoveFiles` separately if file removal is under review. For the forced-exit gate, use a fresh VM checkpoint, stop a confirmed managed Python watcher as an administrator while no real uploads are running, and retry upgrade or uninstall after that exact instance has exited. Expect a disabled task, retained runtime, and an unconfirmed running record that a receipt from another instance cannot satisfy. Restore the VM checkpoint after the negative test. The ordinary rollback path preserves uncertain cleanup records for review.

7. For the Phase 1.3 ledger on DLP-LAB01, retry the same install or uninstall with the updated scripts. Verify that the current cleanup receipt passes its existing checks and the historical `running` records still block. The protected `Instances\MaintenancePlan` now holds a `restart` snapshot, and the matching `RestartWitness-<id>` key exists under `HKLM\SOFTWARE\DLP\ManagedCurl`. Retry on the same boot and verify the hold. Then use **Restart** in Windows and retry the same operation. Confirm no task instance or managed interpreter remains before cutover. Compare the original records byte for byte and check for a separate `RestartEvidence\<instance>\Disposition` marked `abandoned_after_full_restart` for each recovered record. Verify the current watcher’s real receipt still matches its maintenance operation and that the replacement watcher can start at the next eligible logon. Preserve the protected ledger during this procedure. [Windows Restart and Fast Startup](https://learn.microsoft.com/en-us/troubleshoot/windows-client/setup-upgrade-and-drivers/fast-startup-causes-system-hibernation-shutdown-fail)

### Curl notification acceptance

1. Install the reviewed build on DLP-LAB01. Inspect `Get-ScheduledTask -TaskPath '\' -TaskName DLPNotifier`. Confirm the Limited Users Group principal, unfiltered logon trigger and `Parallel` instances policy. Sign in to two eligible standard accounts, A and B, on the same VM. Keep both sessions signed in throughout. Record the account and session IDs with `quser.exe` and use the token probe in the deployment procedure above to capture the watcher logon IDs.
2. Start the loopback receiver, enable BLOCK for the synthetic marker and wait for policy refresh. Record the current end of each private journal and the shared journal. Upload a detectable marker file from A's standard shell with a unique basename, then switch to B and upload a file with a different basename. Keep the other session's notifier running during each upload.
3. For each upload, match the notification to a new `CLIENT_CURL` / `BLOCKED_KILL` record with `termination=CONFIRMED` under the originating account's `%LOCALAPPDATA%\DLP-Curl\dlp_events.log`. Record the event ID, `source.session_id` and `source.logon_luid`, the displayed filename and destination, and the receiver's actual byte count. Check each desktop's notifications, including Notification Center after switching, for the other account's unique basename. The other desktop must have no matching notification and the other account's journal and shared journal must have no matching event. Confirm from each standard account that the other account's private journal is unreadable. A run counts for both accounts only when each has a confirmed local BLOCK and its own notification.
4. On a lab host that supports two concurrent interactive logons of the same account, repeat the two uploads with distinct basenames. Both logons can read the shared per-account journal in this case. Verify each record's logon LUID and session ID match its originating desktop, and check that each notification appears only there. Record the same-account case as unverified if the lab host cannot provide both sessions.
5. Repeat under ALLOW and REPORT_ONLY, and check that only confirmed blocks notify. Exercise an existing shared-module block and verify its usual notification. Sign out and back in while the old journal remains. Verify no replay, then confirm a new block displays. In a disposable lab journal, rotate in a copy of an already shown record and verify a fresh block displays once without the copied alert.

The non-elevated journal and task fixtures are in `agent\dev_tools\test_notify.ps1`.

### DLP-LAB01 manual Phase 2 results, 2026-11-28

The operator reported these observations from Windows VM DLP-LAB01 using `fix/installer-deployment-ux` at base `1b788d1`. After sign-out and sign-in, `DLPCurlAgent` and `DLPNotifier` started automatically in interactive Session 2.

| Policy | Curl and receiver | Native notification | Server record |
| --- | --- | --- | --- |
| BLOCK | `curl_phase2_blocked.txt` matched `INTERNAL_LABEL`. Curl exited with code `15`. The receiver received 32,768 of 270,000 bytes before termination. | Displayed the filename and `127.0.0.1:8765`. | `CLIENT_CURL` / `BLOCKED_KILL` / `INTERNAL_LABEL` at 13:53:00. |
| ALLOW | The clean file completed with 330,000 of 330,000 bytes received, HTTP 200 and Curl exit code `0`. | No blocking notification. | |
| REPORT_ONLY | The sensitive file completed with 270,000 of 270,000 bytes received and Curl exit code `0`. | No blocking notification. | `CLIENT_CURL` / `LOGGED` / `INTERNAL_LABEL` at 14:01:47. |

`DLPNotifier` restarted at 14:05:38 without replaying historical notifications. The operator restored the policy to BLOCK. This run covered Session 2.

The BLOCK result shows a confirmed stop after a partial transfer. Reactive polling allows bytes to reach the receiver before termination, and short uploads can complete between polls.

### DLP-LAB01 concurrent-logon results, 2026-11-28

**PASS WITH CONDITIONS.** The operator verified two distinct test accounts signed in at the same time on DLP-LAB01.

| Account | Session | Logon LUID | Curl exit code | Notification |
| --- | ---: | --- | ---: | --- |
| `DLPTestA` | 4 | `0000000002971e3b` | 15 | Correct blocking notification on its own desktop |
| `DLPTestB` | 5 | `0000000002a33b9d` | 15 | Correct blocking notification on its own desktop |

Each private journal contained exactly one matching `BLOCKED_KILL` event with `termination=CONFIRMED`. The events had distinct IDs, and the operator verified both private journal ACLs. The shared journal had zero matching events. The operator observed zero cross-session notifications.

The receiver recorded two partial transfers of 32,768 of 270,000 bytes each. These results confirm termination after partial delivery under reactive polling.

Direct cross-account journal access and concurrent logons of the same account remain unverified. [Release acceptance](INSTALLER_PYTHON.md#release-acceptance)

### Automated checks on the company Windows host, 2026-11-28

The non-elevated PowerShell suites passed 84 checks across Python setup, migration, Clipboard shutdown, Curl lifecycle and notification. Python discovery passed all 346 tests with the normal non-administrator Windows token. The restricted run failed Chromium startup with Access Denied and passed the other 345 tests. The controlled loopback receiver passed all 12 cases.

The native Curl runtime fixture passed on the branch rerun and on base `1b788d1`. The first branch run failed the fixture's immediate descendant-exit assertion after a worker timeout. The later worker cleanup verification below records the investigation and remediation. These host fixtures are distinct from the operator's VM notification results above.

### Remediation checks on the company Windows host, 2026-11-28

The non-elevated suites passed 86 PowerShell checks and 350 Python tests, including the MSI inventory and enrollment redirect regressions. The controlled loopback receiver passed all 12 cases.

The unmodified fixture passed on base `1b788d1` and reproduced the timeout assertion on the branch. A temporary observer then ran each revision twice serially under the same non-administrator Windows token. Both base runs passed. One branch run passed and the other failed at the original assertion. At that failure the observed descendant had the matching creation time, an exit code of `1` and a native exit timestamp. Its handle returned `WAIT_TIMEOUT` (`258`) on a zero-duration wait, so exit was still unconfirmed at that sample.

At the time of those checks, the fixture, worker and Windows process helper files matched the base revision. The observer preserved the assertion and its deadlines. Native worker-cleanup sign-off remained open.

### Native worker cleanup verification

Run `agent\dev_tools\curl_windows_runtime_check.py --worker-cleanup-only` with a dependency-ready venv from a standard interactive session. Keep the worker and cleanup deadlines. Record the OS build, Python and psutil versions, each exit code, and the last completed case. The fixture independently verifies the synthetic job's members and requires all their process handles to signal when production cleanup returns.

In the pre-fix 20-run comparison, both revisions returned from cleanup before some descendant handles signaled. All 25 such handles signaled on bounded follow-up. The old fixture compared PID and creation-time visibility. The revised fixture checks the exact handle signal. If a run fails, preserve the original result and record the job's lifetime count, verified identities and any unsignaled handles. [Windows process termination](https://learn.microsoft.com/en-us/windows/win32/procthread/terminating-a-process)

After remediation, all ten native cleanup runs passed under a standard interactive token on Windows build 26200 with Python 3.11.9 and psutil 7.2.2. Each run independently verified five signaled job members. Deployment acceptance and its remaining cases are recorded separately. [Release acceptance](INSTALLER_PYTHON.md#release-acceptance)
