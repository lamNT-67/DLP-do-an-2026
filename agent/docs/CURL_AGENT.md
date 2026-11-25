# Curl Agent V1

The Windows watcher discovers native `curl.exe` processes as users run curl in their usual shell. It uses the device's existing enrollment and evaluates policies assigned to `CLIENT_CURL`. Run the watcher from the repository root with the Python environment that already has the Agent dependencies and a lab device's `config.ini`.

```powershell
$env:DLP_LOG_DIR = Join-Path $env:LOCALAPPDATA 'DLP\logs'
python -B agent/curl_agent.py --config C:\DLP\agent\config.ini
```

In **Policies**, activate **CLI - cURL (curl.exe)** on the enrolled device or its group. Start one watcher manually in the lab user's Windows session. It runs with that user's permissions. Stop it with Ctrl+C. The installer has no curl service or scheduled task.

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
- **Polling cannot guarantee prevention.** Curl can send headers or body bytes before suspension, and a fast process can finish between polls. Data buffered by the OS can continue to arrive after suspension. Where content is read, the watcher uses the same regular file handle for inspection and hashing. It excludes mapped network drives, reparse points, and aliases whose opened path cannot be verified. A consistent handle says which file the watcher inspected. Curl may read a different file or bytes that change over time.
- Ctrl+C stops new inspections. The watcher tries to resume any process it suspended and distinguishes an already-exited process from access denial and other OS errors. It retries failures during polling and makes up to three final attempts on shutdown. Forced termination or persistent Windows access denial can leave curl suspended. Restarting the watcher does not recover its prior suspension state.
- `dlp_events.log` records the reason, inspection coverage, policy disposition, and suspension, termination, and resume outcomes. `BLOCKED_KILL` means Windows accepted the termination request and the process handle signaled exit. A BLOCK decision with an already exited process, failed termination, or unconfirmed termination is `LOGGED`. Clean, excepted, out-of-scope, and coverage records are kept locally. Logs contain the file basename, the URL's hostname and port, and rule metadata. The raw command line, credentials, URL path and query, and content samples are omitted.
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
