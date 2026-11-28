# Windows installer and legacy migration

Run `agent\service\install.bat` from a reviewed DLP release source outside the installed and archived trees. Approve UAC and enter enrollment information when prompted. The key prompt masks input. From an already elevated Windows PowerShell 5.1 console, `install.ps1 -NoPrompt` accepts a valid existing enrollment or a reviewed source `agent\config.ini`. A clean unattended install without that file requires `-ServerUrl` and `-EnrollmentKey`. `-Hostname` defaults to the Windows machine name. Caller-supplied keys can appear in command-line auditing. Prefer the masked prompt for interactive use.

Setup discovers PythonCore in both HKLM registry views. `-CurlPython` selects a specific absolute interpreter path. Selection checks the full path and runtime tree, PSF Authenticode and a machine-trusted chain on the executable and core DLL, AMD64 PE headers, and an isolated CPython 3.10–3.14 probe with `venv` and `ensurepip`. Both DLP venvs use the same validated base. The shared venv is built at its final path under `%ProgramFiles%\DLP-Runtimes` before cooperative shutdown begins.

If discovery yields no compatible interpreter, setup checks Python registrations, uninstall entries and Windows Installer product inventory, then tries the pinned AMD64 PSF installer for 3.13.17 or 3.14.9. It downloads into Administrators/SYSTEM staging, checks the release's SHA-256 and signer, installs all-users without PATH, association or launcher changes, and verifies the expected HKLM registration and runtime. Update the pins and repeat the acceptance cases when qualifying a new release. [Python 3.13.17](https://www.python.org/downloads/release/python-31317/), [Python 3.14.9](https://www.python.org/downloads/release/python-3149/), [CPython installer options](https://docs.python.org/3.13/using/windows.html#installing-without-ui)

Exit `0` means the replacement services have live workers, the browser listener belongs to its worker, and the Curl task is ready for the next eligible logon. Exit `3010` means reboot and rerun setup. Exit `1223` means UAC was cancelled. Other failures identify the failed operation and, where applicable, the path or recovery directory.

## Legacy migration and recovery

On a recognized legacy installation, setup reports unsafe owners or ACEs with the exact path, SID, rights, and inheritance. For an unsafe enrollment path, supply the known API URL and device hostname independently of the old INI. Interactive setup prompts for the URL and for a custom hostname. Unattended migration requires `-ServerUrl` and requires `-Hostname` if the device name differs from the Windows machine name. Setup checks the existing bearer token and exact enrolled hostname at that server without following redirects. Use HTTPS for migration. For a non-loopback HTTP endpoint on an isolated lab network, type `LAB` when prompted or supply `-AllowInsecureLabServer`. This deliberately accepts cleartext credentials on that network.

Setup keeps the hostname, server, API token and supported agent and browser settings. On a fresh install, only Administrators and SYSTEM can access the initial configuration. The network agent enrolls first. Setup verifies its saved token, flushes a key-free recovery copy, and atomically replaces the live file before granting Users read-only access and starting the other consumers. A failed replacement leaves the original file private. The server has no read-only check for an unused key. An invalid key or ambiguous fresh registration can fail after cutover has begun.

Use an approved API URL that serves `agent_register.php` and `agent_policy.php` directly. Fresh enrollment rejects HTTP 3xx responses before accepting a token. The installer's saved-token validation also refuses redirects.

The old `C:\DLP` and `C:\ProgramData\DLP` move as directory objects into the printed `%ProgramFiles%\DLP-Setup\<id>` recovery directory. Historical shared logs are under `previous-data\logs` and older agent-local logs remain under `previous-install`. Setup rebuilds scripts, venvs, and NSSM. NSSM comes from the reviewed release bundle or the pinned vendor archive recommended for current Windows. The log directory is protected, with read and append access for standard users on the two pre-created shared journal files. Curl keeps its private journals and cleanup receipts. [NSSM download guidance](https://www.nssm.cc/download), [WinGet archive SHA-256](https://raw.githubusercontent.com/microsoft/winget-pkgs/master/manifests/n/NSSM/NSSM/2.24-101-g897c7ad/NSSM.NSSM.installer.yaml)

Setup rejects links and unexpected identity in the paths it needs to use. A junction inside a discarded executable subtree is retained as part of the opaque archive. Setup never reads code through that subtree. A changed file identity or configuration, a sharing violation, an existing destination at publication, or an unconfirmed worker exit blocks cutover. Prepared data and directories already moved stay in recovery.

Setup disables the verified Clipboard task before requesting worker shutdown. It requests graceful exit through the watcher window when Windows can reach that desktop. If workers remain, setup uses verified process handles to stop the interpreter and, if still running, its venv launcher. An interpreter seen without a verifiable launcher, unreadable process identity, or a process that fails to exit can leave cutover pending for review.

The recovery directory contains `verified-config.ini` and may contain `enrolled-config.ini` from fresh enrollment. Treat these files as credentials. The old directories retain their legacy ACLs and contents, including links. Treat them as untrusted data. Never launch a script, service wrapper or venv from an archive. A legacy token may already have been exposed. Suspected prior privileged execution requires endpoint incident response.

### Manually recover a blocked migration

1. Review the reported object as an administrator. If cutover started, read `%ProgramFiles%\DLP-Setup\pending` to locate the recovery directory. Check which live and archived directories exist. Save a trusted backup of the recoverable data.
2. Confirm service identity in SCM and desktop task identity in Task Scheduler. Fence starts and stop only confirmed DLP services and tasks. For a pre-cutover filesystem problem, the reviewed uninstaller without `-RemoveFiles` can withdraw matching registrations. During a pending cutover, verify and stop matching registrations manually. Use the [Curl lifecycle procedure](CURL_AGENT.md#dlp-lab01-deployment-and-acceptance) to verify Curl cleanup. A missing receipt or inconsistent Curl registration requires review of the protected records and generations. Preserve that evidence.
3. Verify `C:\DLP` and `C:\ProgramData\DLP` are the intended directory objects. Quarantine ambiguous or linked objects without opening their targets. Use administrator-controlled backup or volume inspection if ownership, paths, or handles prevent a safe move. Resolve service and task collisions with their owners. If a confirmed stopped partial DLP registration blocks repair, remove it through SCM or Task Scheduler using its checked identity. Keep protected Curl records and generations together for review.
4. Recover the enrolled token, exact hostname, and API URL from `enrolled-config.ini`, `verified-config.ini`, or the trusted server and backup. Put only the validated INI data in `agent\config.ini` beside a clean reviewed release. An already-registered hostname requires its existing credential or administrator-assisted recovery on the server.
5. Once the live paths and registrations are reconciled, move the `pending` marker aside for the audit record and rerun the reviewed `install.bat`. Keep archived runtimes out of service and task actions. On a disposable VM, a known-good checkpoint is also a recovery option.

### Uninstall

Run the uninstaller from the reviewed release. It shares the setup lock, verifies SCM and Task Scheduler identities, and confirms Curl and shared shutdown before unregistering them. Service deletion uses SCM. `-RemoveFiles` archives the shared directories and removes validated owned Curl releases. Uninstall retains historical archives, private Curl journals, lifecycle evidence and shared venvs under `%ProgramFiles%\DLP-Runtimes`.

## Limits

- Automatic cutover requires fixed, same-volume NTFS for the shared deployment, ProgramData and Program Files. Custom service accounts, nonstandard actions, colliding names, missing ownership evidence, and inaccessible or linked enrollment paths require manual recovery.
- An interrupted cutover blocks unattended retry until an administrator reconciles the state. The directory exchanges and Windows registrations are separate operations. A failed run can leave coverage degraded and staged artifacts on disk. Any restored Curl registration stays disabled after shared cutover begins.
- The selected release source and bundled inputs must stay trusted throughout setup. Pip requirements remain unpinned. The downloaded NSSM archive is pinned to the WinGet manifest. A supplied NSSM depends on administrator review.
- The Windows Installer inventory distinguishes advertised products from installed products before requesting installed names. An unreadable installed product or unresolved inventory stops bootstrap during preflight. A 2026-11-28 read-only check found an advertised per-machine entry whose `InstalledProductName` query returned `0x80004005`. The advertised MSI VM case below checks that this inventory permits the supported bootstrap. [Windows Installer product properties](https://learn.microsoft.com/en-us/windows/win32/msi/product-installproperty)
- An independently started or ambiguous DLP worker can hold cutover. The procedure cannot certify a machine that already ran compromised elevated code.
- Setup requests a demand start for the interactive Clipboard and Notifier tasks after cutover. If Task Scheduler rejects a start, setup preserves the pending recovery state. The signed-out Session 0 result is recorded below. [Task Scheduler status codes](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-error-and-success-constants)

## Release acceptance

**APPROVED WITH CONDITIONS** for `fix/installer-deployment-ux` at base `1b788d1`.

### DLP-LAB01 signed-out NoPrompt results, 2026-11-28

**PASS.** The operator ran the installer as SYSTEM in Session 0 with zero interactive users at launch. The installer and its scheduled task both exited with code `0`. Setup automatically downloaded and installed Python 3.13.17, preserved the existing device enrollment, and deployed the replacement runtimes.

The Browser, Network, and SFTP/SCP services were running. Clipboard, managed Curl, and Notifier started automatically in Session 3 after sign-in. The pending cutover marker was absent.

### Remaining acceptance

- Independent teammate testing will cover a fresh installation on clean Windows and native bootstrap with an advertised MSI entry. The signed-out run exercised automatic Python installation with an existing device enrollment.
- Distinct-account concurrent-logon notification isolation passed within the observed scope. Direct cross-account journal access and same-account concurrent logons remain unverified. [Concurrent-logon results](CURL_AGENT.md#dlp-lab01-concurrent-logon-results-2026-11-28)
- Curl polling can allow partial transfers before termination and miss transfers that finish between polls. [Curl enforcement limits](CURL_AGENT.md#enforcement-and-logging)

## DLP-LAB01 native tests

Use disposable Windows 10 and 11 x64 checkpoints with synthetic credentials and logs. Capture exit status, service and task definitions, before-and-after ACLs, process IDs and creation times, and protected Curl receipts. Apply fixture ACL changes only in the lab.

| Case | Procedure and acceptance |
|---|---|
| Clean Windows | With neither Python nor NSSM, double-click `install.bat`. Verify one UAC prompt, masked enrollment, checked downloads, one enrolled device, and both `pyvenv.cfg` files using the same machine-wide base. Check the shared venv location and browser listener ownership. Sign in again for Curl. |
| AppData and bootstrap | Put per-user Python 3.13 and its launcher first on PATH. Verify fallback to the other pin when appropriate and preserve the user installation, registry, PATH and associations. Repeat for both HKLM views, a valid `-CurlPython` with spaces, and rejected unsigned, x86, AppData, writable and reparse paths. Exercise signature and hash failures and `3010` before any DLP stop. |
| Advertised MSI entry | On a VM with no compatible Python, include an unrelated advertised per-machine MSI entry. Confirm setup can reach the verified all-users Python installer while still detecting genuinely installed Python conflicts. |
| Legacy reproduction | Start the old services and desktop and Curl tasks. Give Authenticated Users Modify on `C:\DLP`, `agent`, and `config.ini`. Use an enrolled device and put synthetic records in the shared and agent-local logs. Confirm exact SID diagnostics, the same server device record, matching archived log hashes, fresh protected code and NSSM, and service actions using the new venv. Repeat after tightening the old ACLs and verify the old tools still enter the archive. |
| Ownership and path ambiguity | Repeat with a user-owned ordinary directory and valid registration. Test foreign service and task definitions, missing token, changed endpoint or hostname, a junction in a required path, a hard-linked INI, and an INI opened for writing. Confirm blocked cases preserve both roots and never open link targets. |
| Enrollment and secrets | Exercise missing or placeholder unattended inputs, a rejected saved token, a wrong returned hostname, and HTTP lab approval. On separate checkpoints make the lab registration endpoint return 307 and 308 with `Location` pointing to an instrumented receiver. Use a synthetic key, verify the receiver gets zero requests, and check that no token is published. Restore the direct endpoint and confirm enrollment and token validation. Cancel UAC and check `%ERRORLEVEL%` is `1223`. Inspect installer output and elevation arguments with a synthetic key. |
| Fresh enrollment config ACL | From a separate standard-user session, verify `C:\DLP\agent\config.ini` is unreadable while enrollment is paused and is read-only with no enrollment key after publication. To test replacement failure, hold the original file open without sharing delete after the network agent saves the token. Verify the live config stays private, the protected token-only recovery copy exists, and the other consumers stay stopped. |
| Preflight failure | Deny dependency or NSSM retrieval or tamper with a disposable copy of the NSSM pin. Compare old services, tasks, the Curl maintenance key and receipts before and after. Existing coverage continues through failed preparation. |
| Shutdown and health | Keep unrelated Python running during upgrade. Verify it survives while owned services and task instances exit before either root moves. Test a stuck worker, a nonzero NSSM result, and a browser-port collision on separate checkpoints. Setup must withhold success. |
| Clipboard shutdown | From a pre-cutover checkpoint, capture the legacy venv launcher and its machine-wide interpreter child, including executable paths, PIDs, parent PID, session, and creation times. Repeat upgrade with workers in the installer desktop and in a separate signed-in session. Verify the owned task is disabled before worker stop, both PIDs exit before either root moves, and a Python process running a disposable `clipboard_agent.py` in another directory survives. Run one case with the task already reporting no instances while both workers are still alive. On a separate checkpoint, leave only an unverified interpreter running from `C:\DLP\agent` and verify setup leaves the worker and pending recovery data for review. |
| Interrupted cutover | On separate checkpoints interrupt only setup after the marker, after one archive rename, and after service creation. Verify unattended retry is held. Use the recovery procedure to rebuild without restarting archived code. |
| Curl upgrade and uninstall | Repeat the two-session, in-flight transfer and incomplete-receipt cases from the [Curl procedure](CURL_AGENT.md#dlp-lab01-deployment-and-acceptance). Verify shared teardown waits for valid cleanup and private journals survive. Test uninstall with and without `-RemoveFiles`. |

### Automatic Python bootstrap

1. Start from a disposable Windows 10 or 11 x64 checkpoint with no DLP installation and no compatible machine-wide Python. Record the PythonCore and uninstall inventory from both HKLM registry views and the current user PATH and Python launcher state. Copy the reviewed release to an administrator-controlled directory. Use synthetic enrollment and the direct lab API.
2. On a second copy of the checkpoint, use an approved inert lab MSI unrelated to Python. In an elevated console, run `msiexec.exe /jm "<absolute path to lab MSI>"`. Query `(New-Object -ComObject WindowsInstaller.Installer).ProductsEx('<lab MSI ProductCode including braces>', '', 4)`. Confirm the product is visible with `InstallProperty('State')` returning `1` (advertised). For an exact reproduction, use an entry whose `InstalledProductName` lookup fails and capture the result. [Windows Installer advertisement](https://learn.microsoft.com/windows-server/administration/windows-commands/msiexec)
3. On each checkpoint, launch the reviewed `install.bat` and approve UAC. Leave `-CurlPython` unset. Capture the installer output and exit status. Expect the pinned PSF download and verified launch, then the expected all-users HKLM registration under Program Files. Check the staged PSF diagnostic log when available and record the pinned version, signer verification and hash. For exit `3010`, verify no DLP cutover occurred, restart Windows, and retry.
4. After exit `0`, compare the `home` entry in the shared and managed Curl `pyvenv.cfg` files. Both must identify the new protected interpreter. Verify the original PATH, launcher and any per-user Python are preserved. On a separate checkpoint install per-user Python from the 3.13 family and confirm setup skips that pin and uses the 3.14 pin when available. A missing installed product name must hold setup before download when the conflict inventory remains unresolved.

### Signed-out NoPrompt deployment

For an isolated signed-out test, use a checkpoint with a compatible protected Python and a valid lab device enrollment. Provide enrollment from the incumbent protected config or a reviewed, Administrators/SYSTEM-only `agent\config.ini` in the staged release. Keep credentials out of the task action and capture files.

1. Place the reviewed release under `C:\Program Files\DLP-Lab\release`. Verify the staging directory and its contents are administrator-controlled. Store the following as `C:\Program Files\DLP-Lab\Run-SignedOutSetup.ps1` on the VM.

   ```powershell
   $lab = 'C:\Program Files\DLP-Lab'
   $setup = Join-Path $lab 'release\agent\service\install.ps1'
   "SessionId=$([Diagnostics.Process]::GetCurrentProcess().SessionId)" |
       Set-Content (Join-Path $lab 'signed-out-context.txt')
   quser.exe *>> (Join-Path $lab 'signed-out-context.txt')
   & (Join-Path $PSHOME 'powershell.exe') -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $setup -NoPrompt *> (Join-Path $lab 'signed-out-setup.txt')
   $code = $LASTEXITCODE
   Set-Content (Join-Path $lab 'signed-out-exit.txt') $code
   exit $code
   ```

2. In an elevated 64-bit Windows PowerShell console on the VM, schedule the wrapper once. Sign out every interactive account before the trigger, including disconnected accounts. Leave the VM at the sign-in screen until setup has had time to finish.

   ```powershell
   $action = New-ScheduledTaskAction -Execute (Join-Path $PSHOME 'powershell.exe') -Argument '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "C:\Program Files\DLP-Lab\Run-SignedOutSetup.ps1"'
   $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(3)
   $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount
   Register-ScheduledTask -TaskName 'DLP-Lab-SignedOutSetup' -Action $action -Trigger $trigger -Principal $principal
   ```

3. Sign in and collect the three capture files and `Get-ScheduledTaskInfo -TaskName DLP-Lab-SignedOutSetup`. Confirm Session 0 and an empty interactive session list at launch. Acceptance requires exit `0`, healthy DLP services, no pending cutover marker, and Clipboard, Notifier and managed Curl task launches at the next eligible sign-in. A demand-start error such as `0x80041320`, a pending marker, or an incomplete service startup fails this case. Preserve the setup and Task Scheduler Operational records and follow the recovery procedure. Remove the one-time lab task after recording the result. [Task Scheduler principals](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtaskprincipal)

Run the non-elevated regressions from the repository root in a shell that permits local scripts. The migration test uses disposable NTFS fixtures and mocks for services, tasks, and enrollment.

```powershell
.\agent\dev_tools\test_installer_python.ps1
.\agent\dev_tools\test_curl_installer.ps1
.\agent\dev_tools\test_installer_migration.ps1
.\agent\dev_tools\test_installer_clipboard_shutdown.ps1
python -B -m unittest discover -s agent\dev_tools -p test_policy_client.py
```
